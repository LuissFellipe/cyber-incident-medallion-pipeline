# ️ CyberShield Analytics — Cybersecurity Data Pipeline

> Pipeline de Engenharia de Dados para análise de Logs de Ataques Cibernéticos, construído com **Modern Data Stack Local** usando arquitetura **Medallion (Bronze → Silver → Gold)**.

---

## ️ Arquitetura

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MODERN DATA STACK LOCAL                          │
│                                                                     │
│  CSV Bruto          Bronze              Silver             Gold     │
│  (Local)    ──►  (Raw Parquet)  ──►  (Cleaned +   ──►  (Fact        │
│                   MinIO S3            LGPD Mask)        Table)      │
│                                                                     │
│   Engine: DuckDB + httpfs extension (SQL nativo para S3/MinIO)    │
│   Storage: MinIO (AWS S3-compatible, via Docker)                  │
│   Viz: Streamlit + Plotly                                         │
│   Packages: UV + pyproject.toml                                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Camadas Medallion

| Camada | Path MinIO | Descrição |
|--------|-----------|-----------|
| **Bronze** | `s3://bronze/cyber_attacks_raw.parquet` | Dado bruto sem transformações; apenas metadado `_ingested_at` |
| **Silver** | `s3://silver/cyber_attacks_clean.parquet` | Tipagem, limpeza, mascaramento LGPD de IPs, remoção de PII |
| **Gold** | `s3://gold/fact_incident_summary.parquet` | Tabela fato agregada por Attack Type × Severity × Protocol |

---

##  Como Executar

### Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- [UV](https://docs.astral.sh/uv/getting-started/installation/) (gerenciador de pacotes Python)
- Python 3.11+

### 1. Clone e prepare o ambiente

```bash
git clone https://github.com/seu-usuario/cyber-pipeline.git
cd cyber-pipeline

# Instala as dependências via UV
uv sync

# Copia o arquivo de configuração
cp .env.example .env
```

### 2. Adicione o dataset

```bash
mkdir -p data
# Coloque o arquivo cybersecurity_attacks.csv em:
# data/cybersecurity_attacks.csv
```

### 3. Suba a infraestrutura (MinIO)

```bash
docker compose up -d

# Aguarde ~10 segundos e verifique os buckets criados:
# http://localhost:9001 (root / password123)
```

### 4. Execute o Pipeline ETL

```bash
# Executa todas as camadas (Bronze → Silver → Gold)
uv run python pipeline_etl.py

# Ou execute camadas individualmente:
uv run python pipeline_etl.py --layer bronze
uv run python pipeline_etl.py --layer silver
uv run python pipeline_etl.py --layer gold
```

### 5. Abra o Dashboard

```bash
uv run streamlit run app_dashboard.py
# Acesse: http://localhost:8501
```

---

##  Estrutura do Projeto

```
cyber-pipeline/
│
├──  docker-compose.yml      # MinIO + auto-criação dos buckets Medallion
├──  pyproject.toml          # Dependências (UV-compatible)
├──  .env.example            # Template de variáveis de ambiente
│
├──  pipeline_etl.py         # Pipeline ETL principal (Bronze/Silver/Gold)
├──  app_dashboard.py        # Dashboard Streamlit
│
├──  data/                   # Dataset CSV de origem (não versionado)
│   └── cybersecurity_attacks.csv
│
└──  pipeline.log            # Log de execução gerado automaticamente
```

---

##  Governança de Dados (LGPD)

O pipeline aplica as seguintes regras na camada **Silver**:

| Campo | Tratamento |
|-------|-----------|
| `Source IP Address` | Mascaramento dos 2 últimos octetos: `103.216.15.12` → `103.216.*.*` |
| `Destination IP Address` | Mesmo mascaramento REGEXP_REPLACE |
| `Payload Data` | **Removido** — contém dados textuais sensíveis |
| `User Information` | **Removido** — PII (Personally Identifiable Information) |
| `Proxy Information` | **Removido** — risco de rastreabilidade |

---

##  Dataset

**cybersecurity_attacks.csv** com ~59.000 registros e 25 colunas:

| Coluna | Tipo Silver | Descrição |
|--------|------------|-----------|
| Timestamp | TIMESTAMP | Data/hora do evento |
| Source/Dest IP | STRING (mascarado) | IPs de origem/destino |
| Protocol | STRING | TCP, UDP, ICMP |
| Packet Length | INTEGER | Tamanho do pacote em bytes |
| Attack Type | STRING | DDoS, Malware, Intrusion... |
| Severity Level | STRING | Low, Medium, High, Critical |
| Anomaly Scores | DOUBLE | Score de 0-100 |
| Malware Indicators | STRING | IoC Detected, Malware Detected |
| Action Taken | STRING | Logged, Blocked, Ignored |

---

## ️ Stack Tecnológica

| Componente | Tecnologia | Função |
|-----------|-----------|--------|
| Storage | **MinIO** (Docker) | Object storage S3-compatible |
| Processamento | **DuckDB** + httpfs | SQL analítico sobre S3/Parquet |
| Formato | **Apache Parquet** | Armazenamento colunar comprimido |
| Dashboard | **Streamlit** + Plotly | Visualização interativa |
| Pacotes | **UV** + pyproject.toml | Gerenciamento moderno de dependências |
| Compressão | **Snappy** | Compressão Parquet padrão |

---

##  Dashboard — Visualizações

- **KPI Cards**: Total de incidentes, tipos de ataque, score médio, eventos com malware, severidade crítica, redes de origem
- **Barras Horizontais**: Volume de incidentes por tipo de ataque (Top 12)
- **Gráfico Rosca**: Distribuição percentual por nível de severidade
- **Heatmap**: Cruzamento Tipo de Ataque × Protocolo
- **Bar + Scatter**: Score de anomalia médio vs. máximo por ataque
- **Stacked Bar**: Ações tomadas por nível de severidade
- **Barras Horizontais**: % de eventos com malware por tipo de ataque
- **Tabela Detalhada**: Top 50 registros com todas as métricas

---

##  Comandos Úteis

```bash
# Verificar status dos containers
docker compose ps

# Ver logs do MinIO
docker compose logs minio

# Acessar console MinIO
open http://localhost:9001  # root / password123

# Parar infraestrutura
docker compose down

# Remover volumes (reset completo)
docker compose down -v

# Executar linter
uv run ruff check .

# Formatar código
uv run ruff format .
```

---

##  Licença

MIT © 2024
