"""
=============================================================================
app_dashboard.py — Cybersecurity Incidents Dashboard
=============================================================================
Dashboard interativo Streamlit que consome a camada Gold do MinIO via DuckDB.

Execução:
  uv run streamlit run app_dashboard.py

Pré-requisitos:
  1. Docker Compose rodando: docker compose up -d
  2. Pipeline executado: uv run python pipeline_etl.py
=============================================================================
"""

import os
import time

import duckdb
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuração da Página Streamlit
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberShield Analytics",
    page_icon="️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# CSS Customizado — Visual Dark/Cyber
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* Fundo e tipografia geral */
    [data-testid="stAppViewContainer"] {
        background-color: #0d1117;
        color: #e6edf3;
    }
    [data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }

    /* Cabeçalho principal */
    .main-header {
        background: linear-gradient(135deg, #1a1f2e 0%, #0d2137 50%, #0a1628 100%);
        border: 1px solid #21d4fd33;
        border-radius: 12px;
        padding: 24px 32px;
        margin-bottom: 24px;
        position: relative;
        overflow: hidden;
    }
    .main-header::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, #21d4fd, #b721ff, #21d4fd);
    }
    .main-header h1 {
        color: #21d4fd;
        font-size: 2rem;
        font-weight: 700;
        margin: 0;
        text-shadow: 0 0 20px #21d4fd55;
    }
    .main-header p {
        color: #8b949e;
        margin: 6px 0 0;
        font-size: 0.9rem;
    }

    /* KPI Cards */
    .kpi-card {
        background: linear-gradient(145deg, #161b22, #1c2333);
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px 24px;
        text-align: center;
        transition: border-color 0.2s;
        position: relative;
        overflow: hidden;
    }
    .kpi-card:hover { border-color: #21d4fd66; }
    .kpi-card .kpi-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #21d4fd;
        text-shadow: 0 0 12px #21d4fd44;
        display: block;
    }
    .kpi-card .kpi-label {
        font-size: 0.78rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-top: 4px;
        display: block;
    }
    .kpi-card .kpi-icon {
        font-size: 1.4rem;
        display: block;
        margin-bottom: 8px;
        opacity: 0.85;
    }

    /* Seções de gráfico */
    .section-header {
        color: #e6edf3;
        font-size: 1.1rem;
        font-weight: 600;
        border-left: 3px solid #21d4fd;
        padding-left: 10px;
        margin: 28px 0 14px;
    }

    /* Badges de severidade */
    .badge-critical { color: #ff6b6b; font-weight: 700; }
    .badge-high     { color: #ffa500; font-weight: 700; }
    .badge-medium   { color: #ffd700; font-weight: 700; }
    .badge-low      { color: #51cf66; font-weight: 700; }

    /* Streamlit overrides */
    .stPlotlyChart { border-radius: 10px; }
    [data-testid="metric-container"] { display: none; }
    .stDataFrame { border-radius: 8px; }
    footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# =============================================================================
# CONEXÃO DUCKDB + MINIO
# =============================================================================

@st.cache_resource(ttl=300, show_spinner=False)
def get_duckdb_connection() -> duckdb.DuckDBPyConnection:
    """
    Retorna conexão DuckDB configurada para o MinIO.
    Cache de 5 minutos evita reconexões desnecessárias no Streamlit.
    """
    load_dotenv()

    endpoint   = os.getenv("MINIO_ENDPOINT",   "http://localhost:9000")
    access_key = os.getenv("MINIO_ACCESS_KEY", "root")
    secret_key = os.getenv("MINIO_SECRET_KEY", "password123")
    region     = os.getenv("MINIO_REGION",     "us-east-1")

    endpoint_host = endpoint.replace("http://", "").replace("https://", "")
    use_ssl       = endpoint.startswith("https://")

    con = duckdb.connect()
    con.execute("INSTALL httpfs; LOAD httpfs;")
    con.execute(f"""
        SET s3_endpoint          = '{endpoint_host}';
        SET s3_access_key_id     = '{access_key}';
        SET s3_secret_access_key = '{secret_key}';
        SET s3_region            = '{region}';
        SET s3_use_ssl           = {str(use_ssl).lower()};
        SET s3_url_style         = 'path';
    """)
    return con


@st.cache_data(ttl=120, show_spinner=False)
def load_gold_data(_con, gold_path: str) -> pd.DataFrame:
    """
    Carrega toda a tabela fato Gold via DuckDB e retorna como DataFrame.
    Cache de 2 minutos; o underscore em _con evita hashing do objeto DuckDB.
    """
    return _con.execute(f"SELECT * FROM read_parquet('{gold_path}')").df()


# =============================================================================
# HELPERS DE VISUALIZAÇÃO
# =============================================================================

PLOTLY_THEME = {
    "paper_bgcolor": "rgba(0,0,0,0)",
    "plot_bgcolor":  "rgba(13,17,23,0.6)",
    "font_color":    "#e6edf3",
    "gridcolor":     "#21262d",
    "colorscale":    px.colors.sequential.Teal,
}

SEVERITY_PALETTE = {
    "LOW":      "#51cf66",
    "MEDIUM":   "#ffd43b",
    "HIGH":     "#ff922b",
    "CRITICAL": "#ff6b6b",
}

ATTACK_PALETTE = px.colors.qualitative.Vivid


def styled_fig(fig: go.Figure, height: int = 380) -> go.Figure:
    """Aplica tema escuro padrão a qualquer figura Plotly."""
    fig.update_layout(
        height=height,
        paper_bgcolor=PLOTLY_THEME["paper_bgcolor"],
        plot_bgcolor=PLOTLY_THEME["plot_bgcolor"],
        font=dict(color=PLOTLY_THEME["font_color"], family="Inter, sans-serif"),
        margin=dict(l=16, r=16, t=40, b=16),
        legend=dict(
            bgcolor="rgba(22,27,34,0.8)",
            bordercolor="#30363d",
            borderwidth=1,
        ),
    )
    fig.update_xaxes(gridcolor=PLOTLY_THEME["gridcolor"], showline=False, zeroline=False)
    fig.update_yaxes(gridcolor=PLOTLY_THEME["gridcolor"], showline=False, zeroline=False)
    return fig


def kpi_card(icon: str, value: str, label: str) -> str:
    return f"""
    <div class="kpi-card">
        <span class="kpi-icon">{icon}</span>
        <span class="kpi-value">{value}</span>
        <span class="kpi-label">{label}</span>
    </div>
    """


# =============================================================================
# SIDEBAR — Filtros
# =============================================================================

def render_sidebar(df: pd.DataFrame) -> pd.DataFrame:
    """Renderiza sidebar de filtros e retorna o DataFrame filtrado."""
    st.sidebar.markdown("##  Filtros")
    st.sidebar.markdown("---")

    # Filtro de Severidade
    severity_options = sorted(df["severity_level"].dropna().unique().tolist())
    selected_severity = st.sidebar.multiselect(
        "Nível de Severidade",
        options=severity_options,
        default=severity_options,
        help="Filtra por nível de gravidade do incidente",
    )

    # Filtro de Tipo de Ataque
    attack_options = sorted(df["attack_type"].dropna().unique().tolist())
    selected_attacks = st.sidebar.multiselect(
        "Tipo de Ataque",
        options=attack_options,
        default=attack_options,
        help="Selecione um ou mais tipos de ataque",
    )

    # Filtro de Protocolo
    protocol_options = sorted(df["protocol"].dropna().unique().tolist())
    selected_protocols = st.sidebar.multiselect(
        "Protocolo",
        options=protocol_options,
        default=protocol_options,
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        "<small style='color:#8b949e'>️ CyberShield Analytics v1.0<br>"
        "Modern Data Stack — DuckDB + MinIO<br>"
        "Arquitetura Medallion (Bronze/Silver/Gold)</small>",
        unsafe_allow_html=True,
    )

    # Aplicar filtros
    mask = (
        df["severity_level"].isin(selected_severity)
        & df["attack_type"].isin(selected_attacks)
        & df["protocol"].isin(selected_protocols)
    )
    return df[mask]


# =============================================================================
# SEÇÕES DO DASHBOARD
# =============================================================================

def render_header() -> None:
    st.markdown("""
    <div class="main-header">
        <h1>️ CyberShield Analytics</h1>
        <p>
            Pipeline de Análise de Ataques Cibernéticos &nbsp;|&nbsp;
            Arquitetura Medallion (Bronze → Silver → Gold) &nbsp;|&nbsp;
            DuckDB + MinIO
        </p>
    </div>
    """, unsafe_allow_html=True)


def render_kpis(df: pd.DataFrame) -> None:
    """Renderiza os KPI Cards na primeira linha do dashboard."""
    total_incidents   = int(df["total_incidents"].sum())
    distinct_attacks  = int(df["attack_type"].nunique())
    avg_anomaly       = float(df["avg_anomaly_score"].mean())
    total_malware     = int(df["malware_detected_count"].sum())
    critical_count    = int(df[df["severity_level"] == "CRITICAL"]["total_incidents"].sum())
    distinct_networks = int(df["unique_source_networks"].sum())

    cols = st.columns(6)
    kpis = [
        ("", f"{total_incidents:,}", "Total de Incidentes"),
        ("️",  str(distinct_attacks),  "Tipos de Ataque"),
        ("", f"{avg_anomaly:.2f}",   "Score Médio Anomalia"),
        ("", f"{total_malware:,}",   "Eventos com Malware"),
        ("", f"{critical_count:,}",  "Severidade Crítica"),
        ("", f"{distinct_networks:,}", "Redes de Origem"),
    ]

    for col, (icon, value, label) in zip(cols, kpis):
        with col:
            st.markdown(kpi_card(icon, value, label), unsafe_allow_html=True)


def render_charts_row1(df: pd.DataFrame) -> None:
    """Linha 1 de gráficos: Ataques por tipo + Distribuição de severidade."""
    col1, col2 = st.columns([3, 2])

    # ── Gráfico 1: Volume de Incidentes por Tipo de Ataque (barras horizontais)
    with col1:
        st.markdown('<div class="section-header"> Volume por Tipo de Ataque</div>',
                    unsafe_allow_html=True)

        attack_df = (
            df.groupby("attack_type", as_index=False)["total_incidents"]
            .sum()
            .sort_values("total_incidents", ascending=True)
            .tail(12)  # Top 12
        )

        fig = px.bar(
            attack_df,
            x="total_incidents",
            y="attack_type",
            orientation="h",
            color="total_incidents",
            color_continuous_scale="Teal",
            labels={"total_incidents": "Incidentes", "attack_type": "Tipo de Ataque"},
            text="total_incidents",
        )
        fig.update_traces(
            texttemplate="%{text:,}",
            textposition="outside",
            marker_line_width=0,
        )
        fig.update_coloraxes(showscale=False)
        st.plotly_chart(styled_fig(fig), use_container_width=True)

    # ── Gráfico 2: Distribuição por Severidade (rosca)
    with col2:
        st.markdown('<div class="section-header"> Distribuição por Severidade</div>',
                    unsafe_allow_html=True)

        sev_df = (
            df.groupby("severity_level", as_index=False)["total_incidents"]
            .sum()
            .sort_values("total_incidents", ascending=False)
        )

        colors = [SEVERITY_PALETTE.get(s, "#8b949e") for s in sev_df["severity_level"]]

        fig = go.Figure(go.Pie(
            labels=sev_df["severity_level"],
            values=sev_df["total_incidents"],
            hole=0.55,
            marker=dict(colors=colors, line=dict(color="#0d1117", width=3)),
            textinfo="percent+label",
            textfont=dict(size=13),
            hovertemplate="<b>%{label}</b><br>%{value:,} incidentes<br>%{percent}<extra></extra>",
        ))
        fig.update_layout(
            annotations=[dict(
                text=f"<b>{sev_df['total_incidents'].sum():,}</b><br><span style='font-size:11px'>total</span>",
                x=0.5, y=0.5,
                font=dict(size=18, color="#e6edf3"),
                showarrow=False,
            )]
        )
        st.plotly_chart(styled_fig(fig, height=400), use_container_width=True)


def render_charts_row2(df: pd.DataFrame) -> None:
    """Linha 2: Heatmap Attack × Protocol + Score de Anomalia por Ataque."""
    col1, col2 = st.columns([2, 3])

    # ── Gráfico 3: Heatmap Ataque × Protocolo
    with col1:
        st.markdown('<div class="section-header">️ Heatmap: Ataque × Protocolo</div>',
                    unsafe_allow_html=True)

        pivot = (
            df.groupby(["attack_type", "protocol"])["total_incidents"]
            .sum()
            .reset_index()
            .pivot(index="attack_type", columns="protocol", values="total_incidents")
            .fillna(0)
        )

        fig = go.Figure(go.Heatmap(
            z=pivot.values,
            x=pivot.columns.tolist(),
            y=pivot.index.tolist(),
            colorscale="Teal",
            hovertemplate="<b>%{y}</b> via <b>%{x}</b><br>%{z:,} incidentes<extra></extra>",
            showscale=True,
        ))
        st.plotly_chart(styled_fig(fig, height=380), use_container_width=True)

    # ── Gráfico 4: Score de Anomalia por Tipo de Ataque (box-like via violin)
    with col2:
        st.markdown('<div class="section-header"> Score de Anomalia por Ataque (Médio vs Máximo)</div>',
                    unsafe_allow_html=True)

        anomaly_df = (
            df.groupby("attack_type", as_index=False)
            .agg(
                avg_anomaly=("avg_anomaly_score", "mean"),
                max_anomaly=("max_anomaly_score", "max"),
            )
            .sort_values("avg_anomaly", ascending=False)
        )

        fig = go.Figure()
        fig.add_trace(go.Bar(
            name="Score Médio",
            x=anomaly_df["attack_type"],
            y=anomaly_df["avg_anomaly"],
            marker_color="#21d4fd",
            opacity=0.85,
        ))
        fig.add_trace(go.Scatter(
            name="Score Máximo",
            x=anomaly_df["attack_type"],
            y=anomaly_df["max_anomaly"],
            mode="markers",
            marker=dict(color="#ff6b6b", size=10, symbol="diamond"),
        ))
        fig.update_layout(barmode="group", legend=dict(orientation="h", y=1.12))
        st.plotly_chart(styled_fig(fig, height=380), use_container_width=True)


def render_charts_row3(df: pd.DataFrame) -> None:
    """Linha 3: Ação tomada × severidade + Malware % por tipo de ataque."""
    col1, col2 = st.columns(2)

    # ── Gráfico 5: Ação Tomada por Severidade (stacked bar)
    with col1:
        st.markdown('<div class="section-header">️ Ação Tomada por Nível de Severidade</div>',
                    unsafe_allow_html=True)

        action_df = (
            df.groupby(["severity_level", "action_taken"])["total_incidents"]
            .sum()
            .reset_index()
        )

        # Ordenação pedagógica de severidade
        sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        action_df["severity_level"] = pd.Categorical(
            action_df["severity_level"], categories=sev_order, ordered=True
        )
        action_df = action_df.sort_values("severity_level")

        fig = px.bar(
            action_df,
            x="severity_level",
            y="total_incidents",
            color="action_taken",
            barmode="stack",
            color_discrete_sequence=ATTACK_PALETTE,
            labels={"total_incidents": "Incidentes", "severity_level": "Severidade",
                    "action_taken": "Ação"},
        )
        st.plotly_chart(styled_fig(fig), use_container_width=True)

    # ── Gráfico 6: % Malware Detectado por Tipo de Ataque
    with col2:
        st.markdown('<div class="section-header"> % Malware Detectado por Ataque</div>',
                    unsafe_allow_html=True)

        malware_df = (
            df.groupby("attack_type", as_index=False)
            .agg(
                malware=("malware_detected_count", "sum"),
                total=("total_incidents", "sum"),
            )
            .assign(pct=lambda x: (100 * x["malware"] / x["total"]).round(2))
            .sort_values("pct", ascending=True)
        )

        fig = px.bar(
            malware_df,
            x="pct",
            y="attack_type",
            orientation="h",
            color="pct",
            color_continuous_scale=[[0, "#51cf66"], [0.5, "#ffd43b"], [1, "#ff6b6b"]],
            labels={"pct": "% com Malware", "attack_type": "Tipo de Ataque"},
            text=malware_df["pct"].apply(lambda v: f"{v:.1f}%"),
        )
        fig.update_traces(textposition="outside", marker_line_width=0)
        fig.update_coloraxes(showscale=False)
        st.plotly_chart(styled_fig(fig), use_container_width=True)


def render_data_table(df: pd.DataFrame) -> None:
    """Tabela detalhada com os principais registros da Gold."""
    st.markdown('<div class="section-header"> Tabela Detalhada — Top Incidentes</div>',
                unsafe_allow_html=True)

    display_cols = [
        "attack_type", "severity_level", "protocol", "action_taken",
        "network_segment", "total_incidents", "avg_anomaly_score",
        "malware_detected_count", "malware_pct", "unique_source_networks",
    ]
    display_df = (
        df[display_cols]
        .sort_values(["total_incidents", "avg_anomaly_score"], ascending=[False, False])
        .head(50)
        .rename(columns={
            "attack_type":            "Tipo de Ataque",
            "severity_level":         "Severidade",
            "protocol":               "Protocolo",
            "action_taken":           "Ação Tomada",
            "network_segment":        "Segmento de Rede",
            "total_incidents":        "Total Incidentes",
            "avg_anomaly_score":      "Score Médio",
            "malware_detected_count": "Malware Detectado",
            "malware_pct":            "% Malware",
            "unique_source_networks": "Redes Origem",
        })
    )

    st.dataframe(
        display_df,
        use_container_width=True,
        height=360,
        hide_index=True,
    )


def render_footer(load_time: float) -> None:
    st.markdown("---")
    st.markdown(
        f"<small style='color:#484f58'>️ CyberShield Analytics &nbsp;|&nbsp; "
        f"Dados carregados em {load_time:.2f}s &nbsp;|&nbsp; "
        f"Powered by DuckDB + MinIO + Streamlit</small>",
        unsafe_allow_html=True,
    )


# =============================================================================
# MAIN — Orquestração do Dashboard
# =============================================================================

def main() -> None:
    load_dotenv()
    gold_path = os.getenv("GOLD_PATH", "s3://gold/fact_incident_summary.parquet")

    render_header()

    # Tenta conectar e carregar os dados
    t0 = time.time()
    try:
        con = get_duckdb_connection()
        df_raw = load_gold_data(con, gold_path)
    except Exception as e:
        st.error(f"""
        ** Erro ao conectar ao MinIO ou carregar os dados.**

        Verifique se:
        1. O Docker está rodando: `docker compose up -d`
        2. O pipeline foi executado: `uv run python pipeline_etl.py`
        3. As variáveis do `.env` estão corretas.

        **Detalhe técnico:** `{e}`
        """)
        st.stop()

    if df_raw.empty:
        st.warning("️ Nenhum dado encontrado na camada Gold. Execute o pipeline ETL primeiro.")
        st.stop()

    # Aplica filtros via sidebar
    df = render_sidebar(df_raw)
    load_time = time.time() - t0

    if df.empty:
        st.warning("️ Nenhum dado corresponde aos filtros selecionados. Ajuste os filtros na barra lateral.")
        st.stop()

    # Renderiza seções do dashboard
    render_kpis(df)

    st.markdown("")  # Espaçamento visual

    render_charts_row1(df)
    render_charts_row2(df)
    render_charts_row3(df)
    render_data_table(df)
    render_footer(load_time)


if __name__ == "__main__":
    main()
