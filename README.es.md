# ForensiX.sh

```bash
███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗®
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║╚██╗██╔╝
█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║ ╚███╔╝ 
██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║ ██╔██╗ 
██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██╔╝ ██╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝
╔════════════════════════════════════════════════════════╗
║      @Xafiq  - Proyecto Final de 4Geeks Academy 2025   ║
╚════════════════════════════════════════════════════════╝
```

ForensiX es una herramienta de análisis forense digital de vanguardia diseñada para automatizar el proceso de recopilación y análisis de evidencia forense de un dispositivo montado. Genera informes detallados para ayudar a comprender la naturaleza y el impacto de los incidentes de seguridad. Esta herramienta se utiliza desde dentro del host objetivo usando el modo forense de Kali USB boot.

## 🚀 Características
- 🔍 **Verificación de Dependencias**: Asegura que todas las herramientas necesarias estén instaladas.
- 🛡️ **Bloqueador de Escritura**: Asegura que no se escriban datos en el dispositivo objetivo durante el análisis.
- 🔢 **Checksums**: Calcula y verifica checksums para asegurar la integridad de los datos.
- 🖥️ **Recopilación de Información del Sistema**: Recopila información detallada de hardware y software.
- 🌐 **Análisis de Red**: Recopila configuración de red, servicios y análisis de tráfico.
- 🔒 **Análisis de Seguridad**: Analiza cuentas de usuario, configuraciones de seguridad y registros.
- 👤 **Recopilación de Información del Usuario**: Extrae información relacionada con el usuario del medio objetivo.
- 📈 **Conexiones Apache**: Analiza los registros de acceso de Apache para obtener detalles de las conexiones.
- 🕒 **Generación de Línea de Tiempo**: Crea una línea de tiempo del ataque basada en archivos de registro.
- 📄 **Generación de Informes HTML**: Genera informes HTML completos con hallazgos y recomendaciones.
- 📑 **Descarga de Informes en PDF**: Descarga informes en formato PDF desde el navegador web.


## 📋 Uso
1. **Asegurar Dependencias**: Ejecuta el script para verificar e instalar cualquier dependencia faltante.
2. **Montar Dispositivo**: Proporciona el dispositivo a ser analizado.
3. **Ejecutar Análisis**: El script realizará varios análisis y recopilará evidencia.
4. **Generar Informes**: Elige el tipo de informe a generar (Completo, Seguridad, Recuperación, Ejecutivo).

## 🛠️ Ejecutar el Script
```bash
sudo ./4n6.sh
```

![alt text](assets/preview.jpg)


## 📊 Tipos de Informes
- **Informe de Análisis Completo**: Informe completo que cubre todos los aspectos del análisis.
- **Informe de Incidente de Seguridad**: Enfocado en hallazgos y recomendaciones relacionadas con la seguridad.
- **Plan de Recuperación**: Proporciona un plan para la recuperación y mitigación del sistema.
- **Presentación Ejecutiva**: Resumen de alto nivel adecuado para partes interesadas ejecutivas.


## 👨‍💻 Autor
Creado por @Xafiq como parte del Proyecto Final de 4Geeks Academy 2025.

