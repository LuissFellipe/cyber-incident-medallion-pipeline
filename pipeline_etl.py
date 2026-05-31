"""
=============================================================================
pipeline_etl.py — Cybersecurity Data Pipeline
=============================================================================
Arquitetura Medallion com DuckDB + MinIO (S3-compatible storage)

Camadas:
  Bronze  → Ingestão bruta do CSV → s3://bronze/cyber_attacks_raw.parquet
  Silver  → Limpeza, tipagem e mascaramento LGPD → s3://silver/cyber_attacks_clean.parquet
  Gold    → Agregação analítica → s3://gold/fact_incident_summary.parquet

Execução:
  uv run python pipeline_etl.py
  uv run python pipeline_etl.py --layer bronze   # Executa somente a camada Bronze
  uv run python pipeline_etl.py --layer silver
  uv run python pipeline_etl.py --layer gold

Pré-requisitos:
  1. Docker Compose rodando: docker compose up -d
  2. Dataset em: data/cybersecurity_attacks.csv
=============================================================================
"""

import argparse
import logging
import sys
import time
from pathlib import Path

import duckdb
from dotenv import load_dotenv
import os

# ---------------------------------------------------------------------------
# Configuração de Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("pipeline.log", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


# =============================================================================
# CONFIGURAÇÃO DA CONEXÃO DUCKDB + MINIO
# =============================================================================

def create_duckdb_connection() -> duckdb.DuckDBPyConnection:
    """
    Cria e retorna uma conexão DuckDB configurada com a extensão httpfs
    apontando para o MinIO local (S3-compatible).

    A extensão httpfs permite ao DuckDB ler e escrever diretamente em
    buckets S3 / MinIO usando SQL nativo — sem necessidade de bibliotecas
    intermediárias como boto3 ou s3fs para as operações do pipeline.
    """
    load_dotenv()

    endpoint   = os.getenv("MINIO_ENDPOINT",   "http://localhost:9000")
    access_key = os.getenv("MINIO_ACCESS_KEY", "root")
    secret_key = os.getenv("MINIO_SECRET_KEY", "password123")
    region     = os.getenv("MINIO_REGION",     "us-east-1")

    # Remove o schema para o endpoint (httpfs espera somente host:porta)
    endpoint_host = endpoint.replace("http://", "").replace("https://", "")
    use_ssl       = endpoint.startswith("https://")

    log.info("Inicializando conexão DuckDB com MinIO em: %s", endpoint)

    con = duckdb.connect()  # Banco em memória; estado persiste via MinIO

    # Instala e carrega a extensão httpfs (habilita suporte a S3/GCS/HTTP)
    con.execute("INSTALL httpfs;")
    con.execute("LOAD httpfs;")

    # Configura as credenciais S3 globais na sessão DuckDB
    con.execute(f"""
        SET s3_endpoint        = '{endpoint_host}';
        SET s3_access_key_id   = '{access_key}';
        SET s3_secret_access_key = '{secret_key}';
        SET s3_region          = '{region}';
        SET s3_use_ssl         = {str(use_ssl).lower()};
        SET s3_url_style       = 'path';
    """)

    log.info("Conexão DuckDB configurada com sucesso.")
    return con


# =============================================================================
# CAMADA BRONZE — Ingestão Bruta
# =============================================================================

def run_bronze(con: duckdb.DuckDBPyConnection) -> None:
    """
    Camada Bronze: Lê o CSV bruto local e persiste no MinIO como Parquet.

    Filosofia da Bronze:
      - ZERO transformações; preservar os dados exatamente como vieram da fonte.
      - Garantir rastreabilidade e reprodutibilidade do pipeline.
      - Adicionar metadados de ingestão (_ingested_at) para auditoria.

    Destino: s3://bronze/cyber_attacks_raw.parquet
    """
    raw_csv = os.getenv("RAW_CSV_PATH", "data/cybersecurity_attacks.csv")
    bronze_path = os.getenv("BRONZE_PATH", "s3://bronze/cyber_attacks_raw.parquet")

    csv_candidates = [Path(raw_csv)]
    if raw_csv == "data/cybersecurity_attacks.csv":
        csv_candidates.append(Path("data/cyber attacks/cybersecurity_attacks.csv"))

    csv_absolute = next(
        (candidate.resolve() for candidate in csv_candidates if candidate.exists()),
        Path(raw_csv).resolve(),
    )
    if not csv_absolute.exists():
        raise FileNotFoundError(
            f"Dataset não encontrado: {csv_absolute}\n"
            "Certifique-se de que o arquivo 'cybersecurity_attacks.csv' está em ./data/"
        )

    log.info("═" * 60)
    log.info("BRONZE | Iniciando ingestão do CSV bruto...")
    log.info("Fonte   : %s", csv_absolute)
    log.info("Destino : %s", bronze_path)

    t0 = time.time()

    # -------------------------------------------------------------------------
    # Query Bronze: Leitura do CSV + adição de metadado de ingestão
    # O DuckDB infere automaticamente os tipos a partir do cabeçalho do CSV.
    # Usamos CURRENT_TIMESTAMP para marcar o momento exato da ingestão.
    # -------------------------------------------------------------------------
    con.execute(f"""
        COPY (
            SELECT
                *,
                CURRENT_TIMESTAMP AS _ingested_at   -- Metadado de auditoria
            FROM read_csv_auto(
                '{csv_absolute}',
                header        = true,
                ignore_errors = true,    -- Linhas malformadas são descartadas com log
                nullstr       = '',      -- Strings vazias → NULL
                dateformat    = '%Y-%m-%d %H:%M:%S'
            )
        )
        TO '{bronze_path}'
        (FORMAT 'parquet', COMPRESSION 'snappy', ROW_GROUP_SIZE 100000);
    """)

    # Validação: conta os registros persistidos
    count = con.execute(f"SELECT COUNT(*) FROM read_parquet('{bronze_path}')").fetchone()[0]
    elapsed = time.time() - t0

    log.info("BRONZE | Concluído em %.2fs | %s registros ingeridos", elapsed, f"{count:,}")
    log.info("═" * 60)


# =============================================================================
# CAMADA SILVER — Limpeza, Tipagem e Governança (LGPD)
# =============================================================================

def run_silver(con: duckdb.DuckDBPyConnection) -> None:
    """
    Camada Silver: Lê da Bronze, aplica limpeza, tipagem e mascaramento de dados.

    Transformações aplicadas:
      1. Tipagem explícita:
           - Timestamp          → TIMESTAMP
           - Packet Length      → INTEGER
           - Anomaly Scores     → DOUBLE
           - Source/Dest Port   → INTEGER
      2. Padronização de texto  → TRIM + UPPER em colunas categóricas
      3. Filtragem de nulos     → Remove linhas sem Timestamp ou Attack Type
      4. Mascaramento LGPD      → Oculta os 2 últimos octetos dos IPs
           Ex: 103.216.15.12  →  103.216.*.* (Source e Destination IP)
      5. Remoção de Payload     → Coluna "Payload Data" descartada (dados sensíveis)
      6. Metadado _processed_at → Carimbo da transformação Silver

    Destino: s3://silver/cyber_attacks_clean.parquet
    """
    bronze_path = os.getenv("BRONZE_PATH", "s3://bronze/cyber_attacks_raw.parquet")
    silver_path = os.getenv("SILVER_PATH", "s3://silver/cyber_attacks_clean.parquet")

    log.info("═" * 60)
    log.info("SILVER | Iniciando limpeza e transformação...")
    log.info("Fonte   : %s", bronze_path)
    log.info("Destino : %s", silver_path)

    t0 = time.time()

    # -------------------------------------------------------------------------
    # Query Silver: Transformações completas em SQL nativo DuckDB
    # -------------------------------------------------------------------------
    con.execute(f"""
        COPY (
            SELECT
                -- ── TIPAGEM ──────────────────────────────────────────────────
                TRY_CAST("Timestamp" AS TIMESTAMP)         AS timestamp,
                TRY_CAST("Source Port" AS INTEGER)         AS source_port,
                TRY_CAST("Destination Port" AS INTEGER)    AS destination_port,
                TRY_CAST("Packet Length" AS INTEGER)       AS packet_length,
                TRY_CAST("Anomaly Scores" AS DOUBLE)       AS anomaly_score,

                -- ── MASCARAMENTO LGPD (IPs) ──────────────────────────────────
                -- Regra: substitui os 2 últimos octetos por '*.*'
                -- Ex.: 103.216.15.12 → 103.216.*.*
                REGEXP_REPLACE(
                    "Source IP Address",
                    '(\d{{1,3}}\.\d{{1,3}})\.\d{{1,3}}\.\d{{1,3}}',
                    '\1.*.*'
                )                                          AS source_ip_masked,

                REGEXP_REPLACE(
                    "Destination IP Address",
                    '(\d{{1,3}}\.\d{{1,3}})\.\d{{1,3}}\.\d{{1,3}}',
                    '\1.*.*'
                )                                          AS destination_ip_masked,

                -- ── TEXTO PADRONIZADO (TRIM + UPPER) ─────────────────────────
                UPPER(TRIM("Protocol"))                    AS protocol,
                UPPER(TRIM("Packet Type"))                 AS packet_type,
                UPPER(TRIM("Traffic Type"))                AS traffic_type,
                UPPER(TRIM("Attack Type"))                 AS attack_type,
                UPPER(TRIM("Attack Signature"))            AS attack_signature,
                UPPER(TRIM("Action Taken"))                AS action_taken,
                UPPER(TRIM("Severity Level"))              AS severity_level,
                UPPER(TRIM("Malware Indicators"))          AS malware_indicators,

                -- ── CAMPOS DE CONTEXTO (sem normalização agressiva) ──────────
                TRIM("Alerts/Warnings")                    AS alerts_warnings,
                TRIM("Network Segment")                    AS network_segment,
                TRIM("Geo-location Data")                  AS geo_location,
                TRIM("Log Source")                         AS log_source,
                TRIM("Device Information")                 AS device_info,
                TRIM("IDS/IPS Alerts")                     AS ids_ips_alerts,
                TRIM("Firewall Logs")                      AS firewall_logs,

                -- NOTA: "Payload Data" e "User Information" foram REMOVIDOS
                -- por conterem dados pessoais sensíveis (conformidade LGPD/GDPR).
                -- "Proxy Information" igualmente removida por risco de rastreabilidade.

                -- ── METADADOS ────────────────────────────────────────────────
                _ingested_at,
                CURRENT_TIMESTAMP                          AS _processed_at

            FROM read_parquet('{bronze_path}')

            -- ── QUALIDADE DE DADOS ────────────────────────────────────────────
            -- Remove registros sem chaves obrigatórias para análise
            WHERE
                "Timestamp"   IS NOT NULL
                AND "Attack Type" IS NOT NULL
                AND TRIM("Attack Type") != ''
        )
        TO '{silver_path}'
        (FORMAT 'parquet', COMPRESSION 'snappy', ROW_GROUP_SIZE 100000);
    """)

    # Validação: mostra distribuição de Attack Type para sanity check
    count = con.execute(f"SELECT COUNT(*) FROM read_parquet('{silver_path}')").fetchone()[0]
    elapsed = time.time() - t0

    log.info("SILVER | Concluído em %.2fs | %s registros limpos", elapsed, f"{count:,}")

    # Log de amostra da distribuição de ataques para validação rápida
    sample = con.execute(f"""
        SELECT attack_type, COUNT(*) AS total
        FROM read_parquet('{silver_path}')
        GROUP BY attack_type
        ORDER BY total DESC
        LIMIT 5
    """).fetchall()

    log.info("SILVER | Top 5 tipos de ataque (validação):")
    for row in sample:
        log.info("         %-30s → %s", row[0], f"{row[1]:,}")

    log.info("═" * 60)


# =============================================================================
# CAMADA GOLD — Agregação Analítica (Fact Table)
# =============================================================================

def run_gold(con: duckdb.DuckDBPyConnection) -> None:
    """
    Camada Gold: Cria a tabela fato 'fact_incident_summary' com métricas
    analíticas prontas para consumo por dashboards e ferramentas de BI.

    Granularidade:
      attack_type × severity_level × protocol × action_taken

    Métricas calculadas:
      - total_incidents        : Contagem de eventos por grupo
      - avg_anomaly_score      : Score médio de anomalia (indicador de ameaça)
      - max_anomaly_score      : Pior caso observado no grupo
      - avg_packet_length      : Tamanho médio dos pacotes (padrão de tráfego)
      - malware_detected_count : Qtd de eventos com IoC ou Malware detectado
      - malware_pct            : % de eventos com indicador de malware no grupo
      - unique_source_networks : Redes de origem únicas (octetos 1 e 2 do IP)
      - unique_dest_networks   : Redes de destino únicas
      - first_seen / last_seen : Janela temporal do grupo

    Destino: s3://gold/fact_incident_summary.parquet
    """
    silver_path = os.getenv("SILVER_PATH", "s3://silver/cyber_attacks_clean.parquet")
    gold_path   = os.getenv("GOLD_PATH",   "s3://gold/fact_incident_summary.parquet")

    log.info("═" * 60)
    log.info("GOLD   | Gerando tabela fato analítica...")
    log.info("Fonte   : %s", silver_path)
    log.info("Destino : %s", gold_path)

    t0 = time.time()

    con.execute(f"""
        COPY (
            WITH base AS (
                -- Lê a camada Silver e cria flag de malware para agregação
                SELECT
                    attack_type,
                    severity_level,
                    protocol,
                    action_taken,
                    network_segment,
                    anomaly_score,
                    packet_length,
                    timestamp,
                    source_ip_masked,
                    destination_ip_masked,
                    CASE
                        WHEN malware_indicators IN ('IOC DETECTED', 'MALWARE DETECTED')
                        THEN 1 ELSE 0
                    END AS has_malware
                FROM read_parquet('{silver_path}')
                WHERE attack_type IS NOT NULL
            )

            SELECT
                -- ── DIMENSÕES (chaves de agrupamento) ────────────────────────
                attack_type,
                severity_level,
                protocol,
                action_taken,
                network_segment,

                -- ── MÉTRICAS DE VOLUME ────────────────────────────────────────
                COUNT(*)                                    AS total_incidents,

                -- ── MÉTRICAS DE ANOMALIA ──────────────────────────────────────
                ROUND(AVG(anomaly_score), 4)                AS avg_anomaly_score,
                ROUND(MAX(anomaly_score), 4)                AS max_anomaly_score,

                -- ── MÉTRICAS DE REDE ─────────────────────────────────────────
                ROUND(AVG(packet_length), 2)                AS avg_packet_length,
                MAX(packet_length)                          AS max_packet_length,

                -- ── MÉTRICAS DE SEGURANÇA ─────────────────────────────────────
                SUM(has_malware)                            AS malware_detected_count,
                ROUND(
                    100.0 * SUM(has_malware) / NULLIF(COUNT(*), 0),
                    2
                )                                           AS malware_pct,

                -- ── MÉTRICAS DE DIVERSIDADE DE REDE ──────────────────────────
                COUNT(DISTINCT source_ip_masked)            AS unique_source_networks,
                COUNT(DISTINCT destination_ip_masked)       AS unique_dest_networks,

                -- ── JANELA TEMPORAL ───────────────────────────────────────────
                MIN(timestamp)                              AS first_seen,
                MAX(timestamp)                              AS last_seen,
                DATE_DIFF('hour', MIN(timestamp), MAX(timestamp))
                                                            AS duration_hours,

                -- ── METADADO ─────────────────────────────────────────────────
                CURRENT_TIMESTAMP                           AS _gold_created_at

            FROM base
            GROUP BY
                attack_type,
                severity_level,
                protocol,
                action_taken,
                network_segment

            ORDER BY
                total_incidents DESC,
                avg_anomaly_score DESC
        )
        TO '{gold_path}'
        (FORMAT 'parquet', COMPRESSION 'snappy');
    """)

    # Validação final: mostra sumário da tabela fato
    result = con.execute(f"""
        SELECT
            COUNT(*)                    AS total_rows,
            SUM(total_incidents)        AS total_incidents,
            COUNT(DISTINCT attack_type) AS distinct_attack_types,
            COUNT(DISTINCT protocol)    AS distinct_protocols,
            ROUND(AVG(avg_anomaly_score), 3) AS overall_avg_anomaly
        FROM read_parquet('{gold_path}')
    """).fetchone()

    elapsed = time.time() - t0

    log.info("GOLD   | Concluído em %.2fs", elapsed)
    log.info("GOLD   | Linhas na fato        : %s", f"{result[0]:,}")
    log.info("GOLD   | Total de incidentes   : %s", f"{result[1]:,}")
    log.info("GOLD   | Tipos de ataque únicos: %s", result[2])
    log.info("GOLD   | Protocolos únicos     : %s", result[3])
    log.info("GOLD   | Score médio anomalia  : %s", result[4])
    log.info("═" * 60)


# =============================================================================
# MAIN — Orquestração do Pipeline
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pipeline ETL — Cybersecurity Logs (Bronze → Silver → Gold)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  uv run python pipeline_etl.py                # Executa todas as camadas
  uv run python pipeline_etl.py --layer bronze # Somente Bronze
  uv run python pipeline_etl.py --layer silver # Somente Silver
  uv run python pipeline_etl.py --layer gold   # Somente Gold
        """,
    )
    parser.add_argument(
        "--layer",
        choices=["bronze", "silver", "gold", "all"],
        default="all",
        help="Camada a executar (default: all)",
    )
    args = parser.parse_args()

    log.info("╔══════════════════════════════════════════════════════════╗")
    log.info("║   CYBERSECURITY DATA PIPELINE — Modern Data Stack Local  ║")
    log.info("║   Arquitetura: Medallion (Bronze → Silver → Gold)        ║")
    log.info("║   Engine: DuckDB + MinIO (S3-compatible)                 ║")
    log.info("╚══════════════════════════════════════════════════════════╝")

    try:
        con = create_duckdb_connection()

        pipeline_start = time.time()

        if args.layer in ("bronze", "all"):
            run_bronze(con)

        if args.layer in ("silver", "all"):
            run_silver(con)

        if args.layer in ("gold", "all"):
            run_gold(con)

        total_elapsed = time.time() - pipeline_start

        log.info(" Pipeline concluído com sucesso em %.2fs!", total_elapsed)
        log.info("   Dashboard: uv run streamlit run app_dashboard.py")

    except FileNotFoundError as e:
        log.error(" Arquivo não encontrado: %s", e)
        sys.exit(1)
    except duckdb.Error as e:
        log.error(" Erro DuckDB: %s", e)
        log.error("   Verifique se o MinIO está rodando: docker compose up -d")
        sys.exit(1)
    except Exception as e:
        log.error(" Erro inesperado: %s", e, exc_info=True)
        sys.exit(1)
    finally:
        con.close()


if __name__ == "__main__":
    main()
