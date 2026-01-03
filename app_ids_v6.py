import streamlit as st
import pandas as pd
import joblib
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time
import base64


# Configuration générale
st.set_page_config(
    page_title="IDS - Détection d'attaques réseau",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🛡️"
)

# CSS 
st.markdown("""
    <style>
    /* Arrière-plan avec image de hacker */
    .stApp {
        background: linear-gradient(rgba(0, 0, 0, 0.85), rgba(0, 0, 0, 0.85)),
                    url('https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=1920&q=80');
        background-size: cover;
        background-attachment: fixed;
        background-position: center;
    }
    
    /* En-tête principal */
    .main-header {
        font-size: 3.5rem;
        font-weight: 700;
        color: #00ff41;
        text-align: center;
        padding: 2rem;
        text-shadow: 0 0 10px #00ff41, 0 0 20px #00ff41, 0 0 30px #00ff41;
        letter-spacing: 2px;
        margin-bottom: 1rem;
        font-family: 'Courier New', monospace;
    }
    
    .sub-header {
        font-size: 1.2rem;
        color: #00ff41;
        text-align: center;
        margin-bottom: 2rem;
        font-family: 'Courier New', monospace;
    }
    
    /* Boîtes d'information */
    .info-box {
        padding: 1.5rem;
        border-radius: 5px;
        background-color: rgba(0, 20, 40, 0.9);
        border: 1px solid #00ff41;
        margin: 1rem 0;
        color: #ffffff;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
    }
    
    /* Cartes métriques */
    .metric-card {
        background: linear-gradient(135deg, rgba(0, 20, 40, 0.95), rgba(0, 40, 80, 0.95));
        padding: 1.5rem;
        border-radius: 5px;
        border: 1px solid #00ff41;
        box-shadow: 0 0 15px rgba(0, 255, 65, 0.2);
        color: #ffffff;
        transition: all 0.3s;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 0 25px rgba(0, 255, 65, 0.4);
    }
    
    .metric-card h3 {
        color: #00ff41;
        font-family: 'Courier New', monospace;
        font-size: 1.3rem;
        margin-bottom: 0.5rem;
    }
    
    /* Carte d'attaque détectée */
    .attack-card {
        padding: 2rem;
        border-radius: 5px;
        background: linear-gradient(135deg, #ff0000, #8B0000);
        color: white;
        text-align: center;
        margin: 0.5rem 0;
        border: 2px solid #ff0000;
        box-shadow: 0 0 20px rgba(255, 0, 0, 0.5);
    }
    
    .attack-card h2 {
        font-size: 1.8rem;
        font-weight: bold;
        margin: 0;
    }
    
    /* Boutons */
    .stButton>button {
        width: 100%;
        background: linear-gradient(90deg, #00ff41 0%, #00cc33 100%);
        color: #000000;
        font-weight: bold;
        border-radius: 5px;
        padding: 0.7rem 1rem;
        border: 2px solid #00ff41;
        transition: all 0.3s;
        font-family: 'Courier New', monospace;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .stButton>button:hover {
        background: linear-gradient(90deg, #00cc33 0%, #00ff41 100%);
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.5);
        transform: translateY(-2px);
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, rgba(0, 20, 40, 0.95), rgba(0, 40, 80, 0.95));
        border-right: 1px solid #00ff41;
    }
    
    [data-testid="stSidebar"] .stRadio label {
        color: #ffffff;
        font-family: 'Courier New', monospace;
        font-size: 1rem;
        padding: 0.5rem;
        transition: all 0.3s;
    }
    
    [data-testid="stSidebar"] .stRadio label:hover {
        background-color: rgba(0, 255, 65, 0.1);
        border-left: 3px solid #00ff41;
        padding-left: 0.8rem;
    }
    
    /* Textes */
    h1, h2, h3, h4, h5, h6 {
        color: #00ff41 !important;
        font-family: 'Courier New', monospace;
    }
    
    p, label, span {
        color: #ffffff !important;
    }
    
    /* Tableau */
    .dataframe {
        background-color: rgba(0, 20, 40, 0.9) !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41;
    }
    
    /* Inputs */
    .stNumberInput input, .stTextInput input {
        background-color: rgba(0, 20, 40, 0.8) !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41 !important;
        font-family: 'Courier New', monospace;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background-color: rgba(0, 20, 40, 0.9);
        border: 1px solid #00ff41;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: #00ff41 !important;
        font-family: 'Courier New', monospace;
    }
    
    /* Messages */
    .stSuccess, .stInfo, .stWarning, .stError {
        background-color: rgba(0, 20, 40, 0.9) !important;
        border-left: 4px solid #00ff41 !important;
        color: #ffffff !important;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background-color: rgba(0, 20, 40, 0.9) !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41 !important;
    }
    
    /* Séparateur */
    hr {
        border-color: #00ff41 !important;
    }
    </style>
""", unsafe_allow_html=True)


# Chargement du pipeline

@st.cache_resource
def load_pipeline():
    try:
        return joblib.load("pipeline_ids_dt.pkl")
    except:
        st.error("ERREUR: Le fichier 'pipeline_ids_dt.pkl' est introuvable.")
        return None

pipeline = load_pipeline()


attack_map = {
    0: "ARP_poisioning",
    1: "DDOS_Slowloris",
    2: "DOS_SYN_Hping",
    3: "MQTT_Publish",
    4: "Metasploit_Brute_Force_SSH",
    5: "NMAP_FIN_SCAN",
    6: "NMAP_OS_DETECTION",
    7: "NMAP_TCP_scan",
    8: "NMAP_UDP_SCAN",
    9: "NMAP_XMAS_TREE_SCAN",
    10: "Thing_Speak",
    11: "Wipro_bulb"
}

attack_severity = {
    "ARP_poisioning": "CRITIQUE",
    "DDOS_Slowloris": "CRITIQUE",
    "DOS_SYN_Hping": "ÉLEVÉE",
    "MQTT_Publish": "MOYENNE",
    "Metasploit_Brute_Force_SSH": "CRITIQUE",
    "NMAP_FIN_SCAN": "MOYENNE",
    "NMAP_OS_DETECTION": "FAIBLE",
    "NMAP_TCP_scan": "MOYENNE",
    "NMAP_UDP_SCAN": "MOYENNE",
    "NMAP_XMAS_TREE_SCAN": "MOYENNE",
    "Thing_Speak": "FAIBLE",
    "Wipro_bulb": "FAIBLE"
}

attack_description = {
    "ARP_poisioning": "Attaque par empoisonnement ARP visant à intercepter le trafic réseau",
    "DDOS_Slowloris": "Attaque DDoS visant à épuiser les ressources du serveur",
    "DOS_SYN_Hping": "Attaque par déni de service utilisant des paquets SYN",
    "MQTT_Publish": "Trafic MQTT suspect ou malveillant",
    "Metasploit_Brute_Force_SSH": "Tentative de force brute SSH via Metasploit Framework",
    "NMAP_FIN_SCAN": "Scan de ports NMAP utilisant des paquets FIN",
    "NMAP_OS_DETECTION": "Détection d'OS via NMAP",
    "NMAP_TCP_scan": "Scan TCP de ports avec NMAP",
    "NMAP_UDP_SCAN": "Scan UDP de ports avec NMAP",
    "NMAP_XMAS_TREE_SCAN": "Scan NMAP Xmas Tree",
    "Thing_Speak": "Trafic ThingSpeak IoT",
    "Wipro_bulb": "Trafic provenant d'ampoule connectée Wipro"
}

attack_category = {
    "ARP_poisioning": "RÉSEAU",
    "DDOS_Slowloris": "RÉSEAU",
    "DOS_SYN_Hping": "RÉSEAU",
    "MQTT_Publish": "RÉSEAU",
    "Metasploit_Brute_Force_SSH": "RÉSEAU",
    "NMAP_FIN_SCAN": "SCAN",
    "NMAP_OS_DETECTION": "SCAN",
    "NMAP_TCP_scan": "SCAN",
    "NMAP_UDP_SCAN": "SCAN",
    "NMAP_XMAS_TREE_SCAN": "SCAN",
    "Thing_Speak": "IoT",
    "Wipro_bulb": "IoT"
}

st.markdown('<h1 class="main-header">SYSTÈME DE DÉTECTION D\'INTRUSIONS</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">[ PLATEFORME AVANCÉE DE CYBERSÉCURITÉ - ANALYSE TEMPS RÉEL ]</p>', unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)
with col1:
    if st.button("DÉTECTION TEMPS RÉEL", use_container_width=True):
        st.session_state.current_page = "ANALYSE MANUELLE"
        st.rerun()
    st.markdown('''<div class="metric-card">
        <h3>DÉTECTION TEMPS RÉEL</h3>
        <p>Analyse automatique des flux réseau avec intelligence artificielle</p>
    </div>''', unsafe_allow_html=True)
with col2:
    if st.button("MACHINE LEARNING", use_container_width=True):
        st.session_state.current_page = "STATISTIQUES"
        st.rerun()
    st.markdown('''<div class="metric-card">
        <h3>MACHINE LEARNING</h3>
        <p>Algorithme de classification haute précision</p>
    </div>''', unsafe_allow_html=True)
with col3:
    if st.button("12 TYPES D'ATTAQUES", use_container_width=True):
        st.session_state.current_page = "DOCUMENTATION"
        st.rerun()
    st.markdown('''<div class="metric-card">
        <h3>12 TYPES D'ATTAQUES</h3>
        <p>Détection multi-catégories (Réseau, Scan, IoT)</p>
    </div>''', unsafe_allow_html=True)

st.markdown("---")


if 'current_page' not in st.session_state:
    st.session_state.current_page = "TABLEAU DE BORD"


with st.sidebar:
    st.markdown("### NAVIGATION SYSTÈME")
    
    # Options de menu avec symboles
    menu_options = {
        " TABLEAU DE BORD": "TABLEAU DE BORD",
        " ANALYSE PAR FICHIER": "ANALYSE PAR FICHIER",
        " ANALYSE MANUELLE": "ANALYSE MANUELLE",
        " STATISTIQUES": "STATISTIQUES",
        " DOCUMENTATION": "DOCUMENTATION"
    }
    
    # Trouver l'index actuel
    menu_keys = list(menu_options.keys())
    current_index = 0
    for i, (key, value) in enumerate(menu_options.items()):
        if value == st.session_state.current_page:
            current_index = i
            break
    
    menu_display = st.radio(
        "",
        menu_keys,
        key="menu_selection",
        index=current_index,
        label_visibility="collapsed"
    )
    
    # Mise à jour de la page actuelle
    selected_page = menu_options[menu_display]
    if selected_page != st.session_state.current_page:
        st.session_state.current_page = selected_page
        st.rerun()
    
    st.markdown("---")
    st.markdown("### PARAMÈTRES")
    show_details = st.checkbox("Afficher les détails avancés", value=True)
    
    st.markdown("---")
    st.markdown(f"**SYSTÈME ACTIF**")
    st.markdown(f"**DATE:** {datetime.now().strftime('%d/%m/%Y')}")
    st.markdown(f"**HEURE:** {datetime.now().strftime('%H:%M:%S')}")


if st.session_state.current_page == "TABLEAU DE BORD":
    st.header("TABLEAU DE BORD - VUE D'ENSEMBLE")
    
    st.markdown("""
    <div class="info-box">
    <h3>À PROPOS DU SYSTÈME IDS</h3>
    <p>Ce système de détection d'intrusions utilise des algorithmes d'apprentissage automatique 
    pour identifier automatiquement 12 types d'attaques réseau différentes en analysant 
    les caractéristiques des flux réseau en temps réel.</p>
    <p><strong>Technologies utilisées:</strong> Machine Learning, Arbres de décision, Analyse comportementale</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### FONCTIONNALITÉS PRINCIPALES")
        st.markdown("""
        - Détection de 12 types d'attaques différentes
        - Analyse en temps réel des flux réseau
        - Import et traitement de fichiers CSV
        - Saisie manuelle de données pour tests
        - Visualisations interactives avancées
        - Rapports détaillés avec niveaux de sévérité
        - Classification par catégorie (Réseau, Scan, IoT)
        """)
        
        if st.button("COMMENCER L'ANALYSE", type="primary", use_container_width=True):
            st.session_state.current_page = "ANALYSE PAR FICHIER"
            st.rerun()
    
    with col2:
        st.markdown("### GUIDE D'UTILISATION")
        st.markdown("""
        **1. ANALYSE PAR FICHIER**
        - Importez un fichier CSV contenant les données réseau
        - Visualisez les statistiques et distributions
        - Exportez les résultats avec horodatage
        
        **2. ANALYSE MANUELLE**
        - Saisissez les 20 caractéristiques requises
        - Obtenez une détection instantanée
        - Consultez le niveau de sévérité
        
        **3. DOCUMENTATION**
        - Consultez la liste complète des variables
        - Accédez aux guides techniques
        - FAQ et support
        """)
        
        if st.button("VOIR LA DOCUMENTATION", use_container_width=True):
            st.session_state.current_page = "DOCUMENTATION"
            st.rerun()
    
    # Graphique des types d'attaques
    st.markdown("### RÉPARTITION DES TYPES D'ATTAQUES DÉTECTABLES")
    
    df_attacks = pd.DataFrame({
        'Attaque': list(attack_map.values()),
        'Sévérité': [attack_severity[a] for a in attack_map.values()],
        'Catégorie': [attack_category[a] for a in attack_map.values()]
    })
    
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.sunburst(
            df_attacks,
            path=['Catégorie', 'Attaque'],
            color='Sévérité',
            color_discrete_map={'CRITIQUE':'#d62728', 'ÉLEVÉE':'#ff7f0e', 'MOYENNE':'#ffbb00', 'FAIBLE':'#2ca02c'},
            title="Classification hiérarchique"
        )
        fig.update_layout(
            height=500,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#00ff41')
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        severity_counts = df_attacks['Sévérité'].value_counts()
        fig = px.bar(
            x=severity_counts.index,
            y=severity_counts.values,
            labels={'x': 'Niveau de sévérité', 'y': 'Nombre d\'attaques'},
            title="Distribution par sévérité",
            color=severity_counts.index,
            color_discrete_map={'CRITIQUE':'#d62728', 'ÉLEVÉE':'#ff7f0e', 'MOYENNE':'#ffbb00', 'FAIBLE':'#2ca02c'}
        )
        fig.update_layout(
            height=500,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#00ff41')
        )
        st.plotly_chart(fig, use_container_width=True)


elif st.session_state.current_page == "ANALYSE PAR FICHIER":
    st.header("ANALYSE PAR IMPORTATION DE FICHIER")
    
    st.markdown("""
    <div class="info-box">
    <strong>INSTRUCTIONS:</strong> Importez un fichier CSV contenant les caractéristiques réseau 
    pour effectuer une détection d'attaques en masse. Le fichier doit contenir les 20 variables requises.
    </div>
    """, unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader(
        "SÉLECTIONNER UN FICHIER CSV",
        type=["csv"],
        help="Le fichier doit contenir les 20 variables requises"
    )
    
    if uploaded_file is not None:
        df_test = pd.read_csv(uploaded_file)
        
        st.success(f"FICHIER CHARGÉ AVEC SUCCÈS - {len(df_test)} entrées détectées")
        
        tab1, tab2 = st.tabs(["APERÇU DES DONNÉES", "STATISTIQUES DESCRIPTIVES"])
        
        with tab1:
            st.markdown("**Premières lignes du fichier:**")
            st.dataframe(df_test.head(10), use_container_width=True)
            st.info(f"DIMENSIONS: {df_test.shape[0]} lignes × {df_test.shape[1]} colonnes")
        
        with tab2:
            st.markdown("**Statistiques descriptives:**")
            st.dataframe(df_test.describe(), use_container_width=True)
        
        if st.button("LANCER LA DÉTECTION", type="primary"):
            with st.spinner("ANALYSE EN COURS..."):
                progress_bar = st.progress(0)
                for i in range(100):
                    time.sleep(0.01)
                    progress_bar.progress(i + 1)
                
                if pipeline:
                    y_pred = pipeline.predict(df_test)
                    df_test["Attack_type_encoder"] = y_pred
                    df_test["Attack_type"] = df_test["Attack_type_encoder"].map(attack_map)
                    df_test["Severity"] = df_test["Attack_type"].map(attack_severity)
                    df_test["Category"] = df_test["Attack_type"].map(attack_category)
                    
                    st.success("DÉTECTION TERMINÉE AVEC SUCCÈS")
                    
                    # Métriques globales
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("TOTAL ANALYSÉ", len(df_test))
                    with col2:
                        st.metric("ATTAQUES UNIQUES", df_test["Attack_type"].nunique())
                    with col3:
                        critical = len(df_test[df_test["Severity"] == "CRITIQUE"])
                        st.metric("MENACES CRITIQUES", critical)
                    with col4:
                        most_common = df_test["Attack_type"].mode()[0]
                        st.metric("PLUS FRÉQUENTE", most_common)
                    
                    # Graphiques
                    st.markdown("### VISUALISATIONS")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Distribution par type d'attaque**")
                        attack_counts = df_test["Attack_type"].value_counts()
                        fig = px.pie(
                            values=attack_counts.values,
                            names=attack_counts.index,
                            title="Répartition des attaques détectées",
                            hole=0.4
                        )
                        fig.update_layout(
                            paper_bgcolor='rgba(0,0,0,0)',
                            plot_bgcolor='rgba(0,0,0,0)',
                            font=dict(color='#00ff41')
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with col2:
                        st.markdown("**Distribution par sévérité**")
                        severity_counts = df_test["Severity"].value_counts()
                        fig = px.bar(
                            x=severity_counts.index,
                            y=severity_counts.values,
                            labels={'x': 'Sévérité', 'y': 'Nombre'},
                            title="Analyse des niveaux de menace",
                            color=severity_counts.index,
                            color_discrete_map={'CRITIQUE':'#d62728', 'ÉLEVÉE':'#ff7f0e', 'MOYENNE':'#ffbb00', 'FAIBLE':'#2ca02c'}
                        )
                        fig.update_layout(
                            paper_bgcolor='rgba(0,0,0,0)',
                            plot_bgcolor='rgba(0,0,0,0)',
                            font=dict(color='#00ff41')
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    
                    # Distribution par catégorie
                    st.markdown("**Distribution par catégorie**")
                    category_counts = df_test["Category"].value_counts()
                    fig = px.bar(
                        x=category_counts.index,
                        y=category_counts.values,
                        labels={'x': 'Catégorie', 'y': 'Nombre'},
                        title="Attaques par catégorie",
                        color=category_counts.values,
                        color_continuous_scale='Reds'
                    )
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#00ff41')
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Tableau des résultats
                    st.markdown("### RÉSULTATS DÉTAILLÉS")
                    st.dataframe(
                        df_test[["Attack_type_encoder", "Attack_type", "Severity", "Category"]],
                        use_container_width=True
                    )
                    
                    # Téléchargement
                    csv = df_test.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="TÉLÉCHARGER LES RÉSULTATS (CSV)",
                        data=csv,
                        file_name=f'ids_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
                        mime='text/csv',
                    )


elif st.session_state.current_page == "ANALYSE MANUELLE":
    st.header("ANALYSE MANUELLE DES CARACTÉRISTIQUES")
    
    st.markdown("""
    <div class="info-box">
    <strong>MODE ANALYSE MANUELLE:</strong> Saisissez les 20 caractéristiques réseau 
    pour effectuer une détection individuelle. Toutes les valeurs doivent être numériques.
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("manual_form"):
        st.subheader("SAISIE DES CARACTÉRISTIQUES")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**CARACTÉRISTIQUES TEMPORELLES**")
            flow_duration = st.number_input("flow_duration", value=0.0, help="Durée du flux réseau")
            flow_iat_max = st.number_input("flow_iat.max", value=0.0, help="Temps inter-arrivée maximum")
            flow_iat_tot = st.number_input("flow_iat.tot", value=0.0, help="Temps inter-arrivée total")
            
            st.markdown("**PAQUETS ET TAUX**")
            fwd_pkts_per_sec = st.number_input("fwd_pkts_per_sec", value=0.0, help="Paquets forward/sec")
            flow_pkts_per_sec = st.number_input("flow_pkts_per_sec", value=0.0, help="Paquets flux/sec")
            fwd_header_size_tot = st.number_input("fwd_header_size_tot", value=0.0, help="Taille en-têtes forward")
            
            st.markdown("**PAYLOAD FORWARD**")
            fwd_pkts_payload_min = st.number_input("fwd_pkts_payload.min", value=0.0)
            fwd_pkts_payload_max = st.number_input("fwd_pkts_payload.max", value=0.0)
            fwd_pkts_payload_tot = st.number_input("fwd_pkts_payload.tot", value=0.0)
            fwd_pkts_payload_avg = st.number_input("fwd_pkts_payload.avg", value=0.0)
        
        with col2:
            st.markdown("**PAYLOAD DU FLUX**")
            flow_pkts_payload_max = st.number_input("flow_pkts_payload.max", value=0.0)
            flow_pkts_payload_tot = st.number_input("flow_pkts_payload.tot", value=0.0)
            flow_pkts_payload_avg = st.number_input("flow_pkts_payload.avg", value=0.0)
            flow_pkts_payload_std = st.number_input("flow_pkts_payload.std", value=0.0)
            
            st.markdown("**SOUS-FLUX ET ACTIVITÉ**")
            fwd_subflow_bytes = st.number_input("fwd_subflow_bytes", value=0.0)
            active_max = st.number_input("active.max", value=0.0)
            active_tot = st.number_input("active.tot", value=0.0)
            active_avg = st.number_input("active.avg", value=0.0)
            
            st.markdown("**FENÊTRES TCP**")
            fwd_init_window_size = st.number_input("fwd_init_window_size", value=0)
            fwd_last_window_size = st.number_input("fwd_last_window_size", value=0)
        
        submitted = st.form_submit_button("ANALYSER", type="primary")
    
    if submitted:
        df_input = pd.DataFrame([{
            "flow_duration": flow_duration,
            "fwd_pkts_per_sec": fwd_pkts_per_sec,
            "flow_pkts_per_sec": flow_pkts_per_sec,
            "fwd_header_size_tot": fwd_header_size_tot,
            "fwd_pkts_payload.min": fwd_pkts_payload_min,
            "fwd_pkts_payload.max": fwd_pkts_payload_max,
            "fwd_pkts_payload.tot": fwd_pkts_payload_tot,
            "fwd_pkts_payload.avg": fwd_pkts_payload_avg,
            "flow_pkts_payload.max": flow_pkts_payload_max,
            "flow_pkts_payload.tot": flow_pkts_payload_tot,
            "flow_pkts_payload.avg": flow_pkts_payload_avg,
            "flow_pkts_payload.std": flow_pkts_payload_std,
            "flow_iat.max": flow_iat_max,
            "flow_iat.tot": flow_iat_tot,
            "fwd_subflow_bytes": fwd_subflow_bytes,
            "active.max": active_max,
            "active.tot": active_tot,
            "active.avg": active_avg,
            "fwd_init_window_size": fwd_init_window_size,
            "fwd_last_window_size": fwd_last_window_size
        }])
        
        with st.spinner("ANALYSE EN COURS..."):
            time.sleep(1)
            if pipeline:
                pred = pipeline.predict(df_input)[0]
                attack_name = attack_map[pred]
                severity = attack_severity[attack_name]
                description = attack_description[attack_name]
                category = attack_category[attack_name]
                
                # Affichage du résultat
                st.markdown("---")
                st.markdown("## RÉSULTAT DE L'ANALYSE")
                
                col1, col2, col3 = st.columns([2, 2, 3])
                
                with col1:
                    st.markdown(f"""
                    <div class="attack-card">
                    <h2>{attack_name}</h2>
                    <p style="font-size: 1rem; margin-top: 10px;">TYPE D'ATTAQUE DÉTECTÉ</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    severity_color = {
                        'CRITIQUE': '#d62728',
                        'ÉLEVÉE': '#ff7f0e',
                        'MOYENNE': '#ffbb00',
                        'FAIBLE': '#2ca02c'
                    }
                    st.markdown(f"""
                    <div style="padding: 2rem; border-radius: 5px; background-color: {severity_color[severity]}; 
                                color: white; text-align: center; border: 2px solid {severity_color[severity]};">
                    <h2>{severity}</h2>
                    <p style="font-size: 1rem; margin-top: 10px;">NIVEAU DE SÉVÉRITÉ</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col3:
                    st.markdown(f"""
                    <div class="info-box">
                    <strong>CATÉGORIE:</strong> {category}<br>
                    <strong>DESCRIPTION:</strong> {description}
                    </div>
                    """, unsafe_allow_html=True)
                
                if show_details:
                    st.markdown("### CARACTÉRISTIQUES ANALYSÉES")
                    with st.expander("Afficher les détails techniques"):
                        st.dataframe(df_input.T, use_container_width=True)


elif st.session_state.current_page == "STATISTIQUES":
    st.header("STATISTIQUES ET VISUALISATIONS")
    
    st.markdown("""
    <div class="info-box">
    <strong>MODULE STATISTIQUES:</strong> Vue d'ensemble complète des types d'attaques, 
    leurs caractéristiques et leurs niveaux de sévérité.
    </div>
    """, unsafe_allow_html=True)
    
    # Tableau récapitulatif
    df_summary = pd.DataFrame({
        'Type d\'attaque': list(attack_map.values()),
        'Catégorie': [attack_category[a] for a in attack_map.values()],
        'Sévérité': [attack_severity[a] for a in attack_map.values()],
        'Description': [attack_description[a] for a in attack_map.values()]
    })
    
    st.markdown("### CATALOGUE DES ATTAQUES")
    st.dataframe(df_summary, use_container_width=True)
    
    # Graphiques
    st.markdown("### ANALYSES GRAPHIQUES")
    
    col1, col2 = st.columns(2)
    
    with col1:
        severity_dist = df_summary['Sévérité'].value_counts()
        fig = px.pie(
            values=severity_dist.values,
            names=severity_dist.index,
            title="Distribution par niveau de sévérité",
            color=severity_dist.index,
            color_discrete_map={'CRITIQUE':'#d62728', 'ÉLEVÉE':'#ff7f0e', 'MOYENNE':'#ffbb00', 'FAIBLE':'#2ca02c'}
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#00ff41')
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        cat_dist = df_summary['Catégorie'].value_counts()
        fig = px.bar(
            x=cat_dist.index,
            y=cat_dist.values,
            title="Distribution par catégorie",
            labels={'x': 'Catégorie', 'y': 'Nombre d\'attaques'},
            color=cat_dist.values,
            color_continuous_scale='Reds'
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#00ff41')
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Matrice de sévérité par catégorie
    st.markdown("### MATRICE CATÉGORIE-SÉVÉRITÉ")
    cross_tab = pd.crosstab(df_summary['Catégorie'], df_summary['Sévérité'])
    fig = px.imshow(
        cross_tab,
        labels=dict(x="Sévérité", y="Catégorie", color="Nombre"),
        title="Matrice de distribution",
        color_continuous_scale='Reds'
    )
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#00ff41')
    )
    st.plotly_chart(fig, use_container_width=True)


elif st.session_state.current_page == "DOCUMENTATION":
    st.header("DOCUMENTATION TECHNIQUE")
    
    tab1, tab2, tab3 = st.tabs(["VARIABLES REQUISES", "GUIDE D'UTILISATION", "FAQ"])
    
    with tab1:
        st.markdown("""
        <div class="info-box">
        Le système de détection nécessite <strong>20 variables numériques</strong> 
        extraites de l'analyse des flux réseau.
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        ### LISTE COMPLÈTE DES VARIABLES
        
        #### CARACTÉRISTIQUES TEMPORELLES
        - **flow_duration**: Durée totale du flux réseau en microsecondes
        - **flow_iat.max**: Temps inter-arrivée maximum entre les paquets
        - **flow_iat.tot**: Temps inter-arrivée total cumulé
        
        #### CARACTÉRISTIQUES DE PAQUETS
        - **fwd_pkts_per_sec**: Nombre de paquets forward transmis par seconde
        - **flow_pkts_per_sec**: Nombre total de paquets du flux par seconde
        - **fwd_header_size_tot**: Taille totale des en-têtes de paquets forward (bytes)
        
        #### PAYLOAD FORWARD
        - **fwd_pkts_payload.min**: Taille minimale du payload des paquets forward
        - **fwd_pkts_payload.max**: Taille maximale du payload des paquets forward
        - **fwd_pkts_payload.tot**: Taille totale cumulée du payload forward
        - **fwd_pkts_payload.avg**: Taille moyenne du payload forward
        
        #### PAYLOAD DU FLUX
        - **flow_pkts_payload.max**: Taille maximale du payload dans le flux
        - **flow_pkts_payload.tot**: Taille totale du payload du flux
        - **flow_pkts_payload.avg**: Taille moyenne du payload du flux
        - **flow_pkts_payload.std**: Écart-type de la taille du payload
        
        #### SOUS-FLUX ET ACTIVITÉ
        - **fwd_subflow_bytes**: Nombre d'octets du sous-flux forward
        - **active.max**: Temps d'activité maximum (microsecondes)
        - **active.tot**: Temps d'activité total cumulé
        - **active.avg**: Temps d'activité moyen
        
        #### FENÊTRES TCP
        - **fwd_init_window_size**: Taille initiale de la fenêtre TCP forward
        - **fwd_last_window_size**: Taille finale de la fenêtre TCP forward
        """)
    
    with tab2:
        st.markdown("""
        ### GUIDE D'UTILISATION DÉTAILLÉ
        
        #### MÉTHODE 1: ANALYSE PAR FICHIER
        
        **Étape 1: Préparation du fichier**
        - Créez un fichier CSV avec les 20 variables requises
        - Assurez-vous que toutes les valeurs sont numériques
        - Vérifiez qu'il n'y a pas de valeurs manquantes
        
        **Étape 2: Importation**
        - Naviguez vers le menu "ANALYSE PAR FICHIER"
        - Cliquez sur "SÉLECTIONNER UN FICHIER CSV"
        - Sélectionnez votre fichier depuis votre ordinateur
        
        **Étape 3: Vérification**
        - Consultez l'aperçu des données importées
        - Vérifiez les statistiques descriptives
        - Assurez-vous que les dimensions sont correctes
        
        **Étape 4: Détection**
        - Cliquez sur "LANCER LA DÉTECTION"
        - Attendez la fin de l'analyse (barre de progression)
        - Consultez les résultats et visualisations
        
        **Étape 5: Export**
        - Téléchargez les résultats en cliquant sur "TÉLÉCHARGER LES RÉSULTATS"
        - Le fichier contiendra les attaques détectées avec leur sévérité
        
        #### MÉTHODE 2: ANALYSE MANUELLE
        
        **Étape 1: Navigation**
        - Sélectionnez "ANALYSE MANUELLE" dans le menu
        
        **Étape 2: Saisie des données**
        - Remplissez les 20 champs avec les valeurs mesurées
        - Les champs sont organisés par catégorie pour faciliter la saisie
        - Utilisez les info-bulles pour obtenir des précisions
        
        **Étape 3: Analyse**
        - Cliquez sur "ANALYSER" en bas du formulaire
        - Le système effectue la prédiction instantanément
        
        **Étape 4: Interprétation**
        - Consultez le type d'attaque détecté
        - Notez le niveau de sévérité (CRITIQUE, ÉLEVÉE, MOYENNE, FAIBLE)
        - Lisez la description de l'attaque
        - Activez les détails avancés pour voir toutes les caractéristiques
        
        #### CONSEILS D'UTILISATION
        
        **Bonnes pratiques:**
        - Vérifiez toujours la cohérence des données avant l'analyse
        - Les valeurs négatives peuvent indiquer des erreurs de mesure
        - Pour les analyses en masse, privilégiez l'import de fichier
        - Consultez régulièrement les statistiques pour identifier les tendances
        
        **Interprétation des résultats:**
        - **CRITIQUE**: Action immédiate requise, menace sérieuse
        - **ÉLEVÉE**: Surveillance renforcée et investigation nécessaires
        - **MOYENNE**: Monitoring standard, attention particulière
        - **FAIBLE**: Information à noter, pas d'action urgente
        """)
    
    with tab3:
        st.markdown("""
        ### FOIRE AUX QUESTIONS (FAQ)
        
        #### QUESTIONS GÉNÉRALES
        
        **Q: Combien de types d'attaques le système peut-il détecter?**  
        R: Le système est capable de détecter 12 types d'attaques différentes, 
        réparties en trois catégories principales: Attaques Réseau (5), Scans (5) et IoT (2).
        
        **Q: Quelle est la précision du modèle de détection?**  
        R: Le modèle utilise un algorithme d'arbre de décision entraîné sur un ensemble 
        de données représentatif d'attaques réelles. La précision dépend de la qualité 
        des données d'entrée et du type d'attaque.
        
        **Q: Le système fonctionne-t-il en temps réel?**  
        R: Oui, le système analyse les données dès qu'elles sont fournies, que ce soit 
        par import de fichier ou saisie manuelle. Le temps de traitement est quasi-instantané.
        
        #### QUESTIONS TECHNIQUES
        
        **Q: Quelles sont les données requises pour l'analyse?**  
        R: Le système nécessite 20 variables numériques spécifiques extraites de l'analyse 
        des flux réseau. Consultez l'onglet "VARIABLES REQUISES" pour la liste complète.
        
        **Q: Comment obtenir ces 20 variables depuis mon réseau?**  
        R: Ces variables peuvent être extraites à l'aide d'outils d'analyse réseau comme 
        Wireshark, tcpdump, ou des sondes de capture de flux (NetFlow, sFlow).
        
        **Q: Que faire si mon fichier CSV n'est pas accepté?**  
        R: Vérifiez que:
        - Le fichier contient exactement les 20 variables requises
        - Les noms de colonnes correspondent exactement à ceux spécifiés
        - Toutes les valeurs sont numériques (pas de texte)
        - Il n'y a pas de valeurs manquantes (NaN)
        
        #### UTILISATION ET DÉPLOIEMENT
        
        **Q: Puis-je utiliser ce système en production?**  
        R: Ce système a été développé à des fins éducatives et de démonstration. 
        Pour un déploiement en production, des tests supplémentaires, une validation 
        approfondie et une adaptation aux spécificités de votre environnement sont recommandés.
        
        **Q: Comment interpréter les niveaux de sévérité?**  
        R:
        - **CRITIQUE**: Menace majeure nécessitant une action immédiate. 
          Isolement et investigation prioritaires.
        - **ÉLEVÉE**: Risque significatif. Surveillance renforcée et analyse approfondie requises.
        - **MOYENNE**: Activité suspecte standard. Monitoring et documentation nécessaires.
        - **FAIBLE**: Activité anormale mineure. À noter pour référence future.
        
        **Q: Que faire lorsqu'une attaque est détectée?**  
        R: Procédure recommandée:
        1. Noter l'heure et le type d'attaque
        2. Analyser le contexte (source, destination, volume)
        3. Consulter les logs système et réseau
        4. Évaluer l'impact potentiel
        5. Isoler la source si nécessaire
        6. Documenter l'incident
        7. Appliquer les contre-mesures appropriées
        8. Informer l'équipe de sécurité
        
        #### DÉPANNAGE
        
        **Q: Le fichier pipeline_ids_dt.pkl est introuvable**  
        R: Assurez-vous que le fichier du modèle ML est présent dans le même répertoire 
        que l'application. Ce fichier contient le modèle entraîné nécessaire pour la détection.
        
        **Q: Les graphiques ne s'affichent pas correctement**  
        R: Vérifiez que vous utilisez un navigateur moderne (Chrome, Firefox, Edge) 
        et que JavaScript est activé.
        
        **Q: L'analyse est très lente**  
        R: Pour les fichiers volumineux (>10000 lignes), le traitement peut prendre 
        quelques secondes. Assurez-vous de fermer les autres applications gourmandes en ressources.
        
        #### CATÉGORIES D'ATTAQUES
        
        **Q: Quelle est la différence entre les catégories RÉSEAU, SCAN et IoT?**  
        R:
        - **RÉSEAU**: Attaques visant à perturber ou compromettre le réseau 
          (DDoS, ARP poisoning, brute force)
        - **SCAN**: Activités de reconnaissance et d'énumération du réseau 
          (scans de ports NMAP, détection d'OS)
        - **IoT**: Trafic lié aux appareils connectés, pouvant être légitime ou malveillant
        
        **Q: Pourquoi certaines attaques IoT sont classées comme FAIBLE?**  
        R: Certains trafics IoT (ThingSpeak, ampoules connectées) peuvent être légitimes 
        mais sont signalés car ils peuvent aussi être utilisés dans des botnets ou des attaques DDoS distribuées.
        """)


st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown("**SYSTÈME IDS - MACHINE LEARNING**")
with col2:
    st.markdown(f"**VERSION 2.0 - {datetime.now().strftime('%Y')}**")
with col3:
    st.markdown("**CYBERSÉCURITÉ AVANCÉE**")

