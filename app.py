import streamlit as st
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
import logging

# --- Configuración Inicial ---
st.set_page_config(page_title="DLP AI Firewall - Español", layout="wide")
logging.basicConfig(level=logging.INFO)

# --- 1. CONFIGURACIÓN DEL MOTOR EN ESPAÑOL ---
# Aquí es donde arreglamos el error. Forzamos a Presidio a usar el modelo 'es_core_news_lg'.
def configurar_motor_espanol():
    # Definimos que para el idioma "es" usaremos el modelo de spacy en español
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "es", "model_name": "es_core_news_lg"}],
    }
    
    # Creamos el proveedor con esa configuración
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()
    
    # Iniciamos el Analyzer con soporte SOLO para español
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["es"])
    return analyzer

# --- 2. DETECTOR DE DNI (Tu lógica personalizada) ---
def crear_detector_dni():
    # Regex: 8 dígitos seguidos de una letra mayúscula
    dni_pattern = Pattern(name="dni_pattern", regex=r"\b\d{8}[A-Z]\b", score=0.95)
    # Importante: Le decimos que este reconocedor funciona para "es"
    dni_recognizer = PatternRecognizer(
        supported_entity="ES_DNI", 
        patterns=[dni_pattern],
        supported_language="es" 
    )
    return dni_recognizer

# --- Carga de Motores (Caché) ---
@st.cache_resource
def load_engines():
    # 1. Cargamos el motor base en español
    analyzer = configurar_motor_espanol()
    
    # 2. Le inyectamos tu detector de DNI
    dni_recognizer = crear_detector_dni()
    analyzer.registry.add_recognizer(dni_recognizer)
    
    # 3. Cargamos el anonimizador
    anonymizer = AnonymizerEngine()
    
    return analyzer, anonymizer

try:
    analyzer, anonymizer = load_engines()
    SETUP_OK = True
except Exception as e:
    st.error(f"❌ Error crítico cargando el motor: {e}")
    st.info("💡 Pista: ¿Has ejecutado 'python -m spacy download es_core_news_lg' en la terminal?")
    SETUP_OK = False

# --- Interfaz Gráfica ---
st.title("🛡️ SafePrompt Gateway (Solo Español)")
st.markdown("### Sistema DLP optimizado para normativa española (ISO 27001)")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Entrada de Datos")
    # Texto de ejemplo predefinido para la demo
    texto_demo = "El cliente con DNI 98765432K ha solicitado un aumento. Su teléfono es 612345678 y su correo es juan.perez@example.com."
    
    user_input = st.text_area("Consulta:", height=200, value=texto_demo)
    
    analyze_button = st.button("Analizar Tráfico")

if SETUP_OK and analyze_button and user_input:
    # 1. Análisis (FORZADO A ESPAÑOL 'es')
    # Al haber configurado el NlpEngineProvider arriba, ahora 'es' sí funciona.
    results = analyzer.analyze(text=user_input, language='es')
    
    # 2. Anonimización
    anonymized_result = anonymizer.anonymize(text=user_input, analyzer_results=results)
    
    # 3. Lógica de Alerta
    detected_types = [entity.entity_type for entity in results]
    
    if detected_types:
        st.error(f"🚫 BLOQUEADO. Entidades detectadas: {list(set(detected_types))}")
        
        # Mensajes específicos según lo encontrado
        if "ES_DNI" in detected_types:
            st.toast("Documento Nacional de Identidad detectado", icon="🚨")
        if "PHONE_NUMBER" in detected_types:
             st.toast("Número de teléfono detectado", icon="📞")
            
    else:
        st.success("✅ Tráfico Seguro. No se detectaron datos sensibles.")

    with col2:
        st.subheader("Salida Sanitizada")
        st.code(anonymized_result.text, language="text")
        
        if results:
            with st.expander("🔍 Ver Análisis Técnico (JSON)"):
                st.json([r.to_dict() for r in results])