# 🛡️ SafePrompt Gateway - DLP para IA Generativa
**Trabajo de Asignatura: Implementación de sistema DLP basado en ISO 27001**

### 👥 Equipo
* **Estudiante 1:** [Álvaro]


### 📖 Descripción
Este prototipo implementa el control **A.8.12 de la norma ISO/IEC 27001:2022**. 
Actúa como un *middleware* de seguridad que intercepta y anonimiza datos sensibles (PII) antes de que sean enviados a herramientas de IA externas.

### 🛠️ Cómo ejecutar este proyecto

1. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_lg