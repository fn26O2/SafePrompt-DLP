import streamlit as st
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
import logging

# --- Configuración de la Página ---
st.set_page_config(page_title="SafePrompt Gateway", page_icon="🛡️", layout="wide")

# --- Estilos CSS ---
st.markdown("""
    <style>
    .stTextArea textarea {
        font-family: 'Courier New', Courier, monospace;
    }
    </style>
""", unsafe_allow_html=True)

# --- 1. CONFIGURACIÓN DEL MOTOR EN ESPAÑOL ---
def configurar_motor_espanol():
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "es", "model_name": "es_core_news_lg"}],
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["es"])
    return analyzer

# --- 2. DETECTOR DE DNI ---
def crear_detector_dni():
    dni_pattern = Pattern(name="dni_pattern", regex=r"\b\d{8}[A-Z]\b", score=0.95)
    dni_recognizer = PatternRecognizer(
        supported_entity="ES_DNI", 
        patterns=[dni_pattern],
        supported_language="es" 
    )
    return dni_recognizer

# --- Carga de Motores ---
@st.cache_resource
def load_engines():
    try:
        analyzer = configurar_motor_espanol()
        dni_recognizer = crear_detector_dni()
        analyzer.registry.add_recognizer(dni_recognizer)
        anonymizer = AnonymizerEngine()
        return analyzer, anonymizer, True
    except Exception as e:
        return None, None, False

analyzer, anonymizer, SETUP_OK = load_engines()

# --- INTERFAZ GRÁFICA ---

col_logo, col_title = st.columns([1, 15])
with col_logo:
    st.markdown("# 🛡️") 
with col_title:
    st.title("SafePrompt Gateway (Prototipo ISO 27001)")
    st.markdown("Esta herramienta actúa como un **proxy de seguridad** (DLP) para evitar fugas de información al usar IAs como ChatGPT. Cumple con el control **A.8.12 de ISO 27001:2022**.")

st.write("") 

if not SETUP_OK:
    st.error("❌ Error crítico: No se pudo cargar el motor. Ejecuta: `python -m spacy download es_core_news_lg`")
else:
    # --- ÁREA PRINCIPAL ---
    col1, col2 = st.columns(2)
    texto_salida = ""
    entidades_detectadas = []
    
    with col1:
        st.subheader("1. Área de Empleado (Riesgo)")
        texto_demo = """Genera un informe que incluya los siguientes datos sensibles:
Nombre: Juan Pérez
Dirección: Calle Ejemplo 123, Ciudad de México, CP 01010
Número de teléfono: +52 55 1234 5678
Correo electrónico: juan.perez@email.com
Número de identificación: 12345678Z
El informe debe analizar las implicaciones de seguridad."""

        texto_entrada = st.text_area("Escribe tu consulta para la IA aquí:", height=350, value=texto_demo)
        analizar = st.button("Analizar y Enviar de forma Segura", type="primary")

    # Lógica de Análisis
    if analizar and texto_entrada:
        results = analyzer.analyze(text=texto_entrada, language='es')
        anonymized_result = anonymizer.anonymize(text=texto_entrada, analyzer_results=results)
        texto_salida = anonymized_result.text
        entidades_detectadas = [entity.entity_type for entity in results]

    with col2:
        st.subheader("2. Salida Segura (Lo que viaja a Internet)")
        st.text_area("Texto Sanitizado:", value=texto_salida if analizar else "", height=350, disabled=True)
        
        if analizar:
            st.info("ℹ️ Solo esta información anonimizada llega a los servidores de la IA.")
            st.warning("Los datos originales han sido suprimidos o enmascarados.")

    # --- ALERTAS ---
    if analizar and entidades_detectadas:
        st.error(f"⚠️ ¡ALERTA DLP! Se han detectado datos sensibles: {list(set(entidades_detectadas))}")
        with st.expander("Ver detalles técnicos de la detección (JSON)"):
            st.json([r.to_dict() for r in results])
    elif analizar:
        st.success("✅ Tráfico limpio. No se detectaron riesgos.")

    # --- PIE DE PÁGINA SIMPLE ---
    st.divider()
    m1, m2, m3 = st.columns(3)
    m1.metric("Estado del Sistema", "Activo", "En línea")
    m2.metric("Motor DLP", "Microsoft Presidio", "v2.0")
    m3.metric("Cumplimiento", "ISO 27001", "A.8.12")