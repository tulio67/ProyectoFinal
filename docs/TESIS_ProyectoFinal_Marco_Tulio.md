# Proyecto Final – Aseguramiento de la Calidad del Software
Pruebas manuales y automatizadas sobre Buggy Cars Rating (https://buggy.justtestit.org/) con Playwright

Autor: Marco Tulio  
Curso: Aseguramiento de la Calidad del Software  
Fecha: Octubre 2025  
Repositorio: https://github.com/tulio67/ProyectoFinal  
Idioma principal del repositorio: JavaScript  
Branch por defecto: master  
ID del repositorio: 1085438928

------------------------------------------------------------

Tabla de contenido
1. Resumen ejecutivo
2. Abstract (English)
3. Introducción
4. Marco teórico
5. Metodología de prueba
6. Alcance, supuestos y limitaciones
7. Arquitectura de pruebas, herramientas y configuración
8. Diseño de casos de prueba
9. Ejecución y resultados
10. Análisis de fallos y gestión de riesgos
11. Recomendaciones
12. Conclusiones
13. Trabajo futuro
14. Referencias
15. Anexos
   A. Casos de prueba (detalle)
   B. Bitácora de defectos (ERRO-001 a ERRO-013)
   C. Evidencias y comandos
   D. Extractos de configuración (Playwright)

------------------------------------------------------------

1. Resumen ejecutivo
Este informe consolida los resultados de las pruebas funcionales y de seguridad realizadas en la aplicación web https://buggy.justtestit.org/ entre el 16/10/2025 y el 20/10/2025. El objetivo principal fue verificar:
- Validación de formularios (frontend y backend),
- Gestión de sesiones y autenticación,
- Políticas de contraseñas y bloqueo por intentos fallidos,
- Manejo de rutas/recursos inexistentes,
- Experiencia de usuario en registro, login, perfil y votación.

Alcance: módulos de registro (/register), autenticación, edición de perfil (Additional Info) y sistema de votación (Buggy Rating), en Windows 11 y MacOS Sequoia 15.6.1, usando Chrome y Safari. Los hallazgos fueron reportados por los testers Marco Tulio Lara Salazar y Marco Lara.

Metodología: combinación de pruebas manuales exploratorias y de casos predefinidos, más una batería de pruebas automatizadas con Playwright Testing. Se verificaron comportamientos en frontend (validaciones, mensajes y UX) y backend (respuestas HTTP, persistencia y políticas de seguridad).

Hallazgos: 13 incidencias principales (ERRO-001 a ERRO-013) relacionadas con validaciones incompletas, sesiones sin expiración adecuada, inexistencia de bloqueo por múltiples intentos fallidos, reutilización de contraseñas, manejo deficiente de modelos inexistentes y retrasos en carga de imágenes. Cuatro defectos con prioridad alta, siete media y dos baja.

Recomendación inmediata: abordar primero las vulnerabilidades y validaciones críticas (bloqueo por intentos, políticas de contraseñas, expiración de sesión, saneamiento de entradas), luego mejorar el manejo de errores (rutas inexistentes) y optimizar recursos multimedia.

Métricas clave (automatización):
- 93 casos de prueba automatizados
- 75 pruebas exitosas (80.6% de éxito)
- 7 archivos de especificación
- 3 navegadores validados (Chrome, Firefox, Safari)
- 6 categorías de pruebas

------------------------------------------------------------

2. Abstract (English)
This thesis-like report covers functional and security testing for the web application https://buggy.justtestit.org/ (Oct 16–20, 2025), focusing on form validation, session and authentication management, password policies and brute force mitigation, routing and nonexistent resources handling, and user experience in key flows (registration, login, profile, and rating). The scope included manual test cases and exploratory testing, alongside automated end-to-end tests built with Playwright across Chrome, Firefox, and Safari on Windows 11 and macOS Sequoia 15.6.1. We identified 13 key issues regarding missing validations, session timeout, lack of login attempt throttling, password reuse, improper handling of nonexistent models, and image loading delays. We recommend prioritizing critical security fixes before improving error handling and asset optimization. Automated test metrics: 93 tests, 75 passed (80.6%), 7 specs, 3 browsers validated.

------------------------------------------------------------

3. Introducción
Contexto: El aseguramiento de la calidad (QA) en aplicaciones web requiere validar no solo la funcionalidad base, sino también la seguridad, la robustez ante errores y la experiencia de usuario. Buggy Cars Rating ofrece flujos representativos (registro, autenticación, perfil, votación) adecuados para aplicar buenas prácticas de prueba.

Objetivo general: Evaluar integralmente la calidad de la aplicación, combinando pruebas manuales y automatizadas, para identificar defectos críticos, medir la estabilidad funcional, y proponer mejoras priorizadas.

Objetivos específicos:
- Implementar un framework de pruebas automatizadas con Playwright (multi-navegador).
- Validar reglas de negocio y políticas de seguridad clave (XSS, SQLi, contraseñas).
- Medir cobertura funcional y rendimiento percibido (tiempos de carga de imágenes).
- Documentar metodología, resultados, defectos y recomendaciones profesionales.

Valor del repositorio (tulio67/ProyectoFinal): Contiene la configuración de Playwright (JavaScript), scripts de ejecución, y documentación técnica (README, Informe técnico y Resumen ejecutivo) que respaldan la reproducibilidad y la difusión de resultados.

------------------------------------------------------------

4. Marco teórico
- Tipos de pruebas: funcionales, de validación de entradas, de seguridad (OWASP), usabilidad y compatibilidad cross-browser.
- Seguridad web:
  - OWASP Top 10: XSS, inyección (SQLi), autenticación rota, gestión de sesiones.
  - Políticas de contraseñas: complejidad, no reutilización, verificación del cambio, bloqueo por intentos fallidos.
- Automatización E2E:
  - Playwright: ejecución paralela, pruebas deterministas, trazas, soporte multi-navegador.
- Experiencia de usuario (UX):
  - Mensajería clara en errores/éxitos, retroalimentación al usuario (notificaciones), placeholders/skeletons, rendimiento percibido.

------------------------------------------------------------

5. Metodología de prueba
- Enfoque mixto:
  1) Pruebas manuales con casos definidos por área funcional (Registro, Login, Perfil, Cambio de contraseña, Votación, Comentarios, Navegación/Contenido, Errores/Validaciones), con resultados esperados y códigos de error (ERRO-001 a ERRO-013).
  2) Pruebas exploratorias para detectar comportamientos no previstos (timeout de sesión, rutas inexistentes, UX).
  3) Pruebas automatizadas con Playwright en 3 navegadores, con ejecución paralela y reporter HTML.
- Evidencias: bitácora de defectos, clasificación por prioridad, recomendaciones técnicas y estratégicas.

------------------------------------------------------------

6. Alcance, supuestos y limitaciones
- Alcance:
  - Módulos: /register, autenticación, perfil (Additional Info), Buggy Rating.
  - Validaciones front y backend de campos, políticas de contraseñas, bloqueo por intentos, manejo de modelos inexistentes, rendimiento de recursos visuales.
- Supuestos:
  - Políticas estándar de seguridad (no reutilización de contraseñas, bloqueo por intentos, expiración de sesión ~15–30 min).
  - Conectividad estable, datos de prueba consistentes, entorno de prueba accesible.
- Limitaciones:
  - Sin acceso al código backend ni a logs del servidor.
  - Variaciones de red pueden afectar tiempos de carga percibidos.
  - Algunas pruebas de rendimiento se basan en observaciones de UX (sin perfiles de red profundos).

------------------------------------------------------------

7. Arquitectura de pruebas, herramientas y configuración
- Tecnologías utilizadas:
  - Playwright v1.56.1 (automatización E2E)
  - Node.js v22.12.0
  - JavaScript ES6+
  - Git & GitHub (control de versiones)
- Repositorio y estructura principal:
  - master
  - Archivos principales:
    - README.md, INFORME_TECNICO.md, RESUMEN_EJECUTIVO.md
    - PROJECT_CONFIG.md (convenciones del proyecto)
    - playwright.config.js (config E2E)
    - package.json / package-lock.json
    - tests/ (especificaciones)
- Configuración de Playwright (síntesis):
  - testDir: ./tests
  - fullParallel: true
  - retries: 2 en CI
  - reporter: html
  - use: { trace: 'on-first-retry' }
  - projects: chromium, firefox, webkit
- Scripts npm (síntesis):
  - npx playwright test
  - npx playwright show-report
  - Targets específicos: login.spec.js, register.spec.js, security-tests.spec.js, smoke.spec.js
- Entornos:
  - Windows 11 y MacOS Sequoia 15.6.1
  - Navegadores: Chrome, Firefox, Safari

------------------------------------------------------------

8. Diseño de casos de prueba
Áreas cubiertas:
- Registro de usuario:
  - Campos requeridos, formato, longitud, contraseñas coincidentes, contraseñas débiles, caracteres inválidos, espacios y longitudes extremas.
- Autenticación e inicio/cierre de sesión:
  - Credenciales válidas/ inválidas, case sensitivity, expiración de sesión, recuperación de credenciales, bloqueo por intentos.
- Perfil de usuario:
  - Edición de First/Last Name, validaciones de Gender (selector), Age (numérico), Address/Phone.
- Cambio de contraseña:
  - Complejidad, no reutilización, no igualdad a la actual.
- Votación:
  - Emisión de voto logueado/no logueado, voto duplicado, modelo inexistente.
- Comentarios:
  - Comentario requerido/opcional, longitudes máximas, XSS.
- Navegación/Contenido:
  - Carga de modelos, errores 404, persistencia de sesión tras refresh, rendimiento de imágenes.
- Errores y validaciones:
  - XSS bloqueado, SQLi bloqueado.

Los casos de prueba manuales detallados se incluyen íntegramente en el Anexo A.

------------------------------------------------------------

9. Ejecución y resultados
9.1. Resultados manuales (resumen)
- Total de incidencias: 13 (ERRO-001 a ERRO-013)
- Priorización:
  - Alta: ERRO-001 (campos vacíos sin validación), ERRO-04 (sin “Olvidé mi contraseña”), ERRO-05 (sin bloqueo por intentos), ERRO-13 (retrasos de imágenes)
  - Media: ERRO-02, ERRO-03, ERRO-07, ERRO-08, ERRO-09, ERRO-10, ERRO-11, ERRO-12
  - Baja: Algunos escenarios de validación y UX no críticos

9.2. Resultados automatizados (Playwright)
- 93 casos implementados
- 75 pasaron (80.6%)
- 7 especificaciones
- 3 navegadores validados
- Categorías: Autenticación, Registro, Navegación, Validaciones, Seguridad (SQLi/XSS), Funcionalidades (Perfil, Rating, Responsividad)

9.3. Seguridad
- Inyección SQL: protegido (bloqueo de patrones típicos)
- XSS: protegido (encoding/filtrado observado)
- Límite de intentos: no implementado (riesgo de brute force)
- Políticas de contraseñas: permitir reutilización y “misma actual” en cambio (riesgo)

9.4. Compatibilidad y UX
- Consistencia de UI mayormente adecuada en Chrome, Firefox, Safari
- Algunos fallos menores de selectores/elementos
- Retrasos notables de imágenes sin skeletons/placeholders

------------------------------------------------------------

10. Análisis de fallos y gestión de riesgos
10.1. Distribución de fallos (automatización)
- 12 fallos por selectores duales/ambigüedad en UI (bajo impacto)
- 4 fallos por elementos de navegación (textos diferentes)
- 2 fallos de responsividad móvil (elemento no encontrado)
Impacto: bajo sobre funcionalidades core

10.2. Riesgos priorizados
- R1 (Alto): Sin bloqueo por intentos fallidos (ERRO-05) – riesgo de fuerza bruta
- R2 (Alto): Sin recuperación visible de credenciales (ERRO-04) – UX y seguridad de cuentas
- R3 (Alto): Retrasos en imágenes (ERRO-13) – percepción de rendimiento, tasa de rebote
- R4 (Medio): Sesiones que no expiran (ERRO-03) – exposición en equipos compartidos
- R5 (Medio): Reutilización/igualdad de contraseñas (ERRO-09/10) – degradación de seguridad
- R6 (Medio): Validaciones de entradas inconsistentes (ERRO-01/02/06/07/08/12) – integridad de datos

10.3. Causas probables (hipótesis)
- Frontend: validaciones HTML5/JS incompletas, falta de máscaras/componentes tipados
- Backend: endpoints sin throttling, sin historial de contraseñas, códigos HTTP no diferenciados para recursos inexistentes
- Recursos: imágenes sin optimización (peso/dimensión), sin estrategias de caching/precarga

------------------------------------------------------------

11. Recomendaciones
11.1. Técnicas (corto plazo)
- Seguridad:
  - Bloqueo por intentos: rate limiting (IP/usuario), backoff exponencial, captcha
  - Políticas de contraseñas: historial (N anteriores), complejidad y verificación contra “misma actual”
  - Expiración de sesión: TTL corto para cookies de sesión y renovación con actividad
- Validaciones:
  - Frontend: data-testid para selectores; <input type="number"> en Age; select bloqueado en Gender
  - Backend: validación server-side simétrica; normalización y saneamiento de entradas
- UX y rendimiento:
  - Mensajes claros en voto sin comentario; skeleton loaders; imágenes responsive y lazy-loading; cache-control/CDN

11.2. Estratégicas (mediano plazo)
- CI/CD: integrar pipeline en GitHub Actions para ejecutar suite Playwright en PRs
- Cobertura: ampliar a pruebas de rendimiento (Lighthouse), accesibilidad (axe), y mobile viewports
- Observabilidad: paneles de métricas y alertas sobre tasas de error, respuesta y UX (Core Web Vitals)

11.3. Debt técnico y documentación
- Estandarizar nomenclatura de menús y textos
- Guías de desarrollo seguro y convenciones de validación
- Plantillas de defectos y criterios de aceptación por módulo

------------------------------------------------------------

12. Conclusiones
- Funcionalidad: El 80.6% de éxito en automatización, sumado a los flujos manuales aprobados, refleja una base sólida.
- Seguridad: Protecciones efectivas contra XSS y SQLi; pendientes críticos en bloqueo por intentos y políticas de contraseñas/expiración de sesión.
- Compatibilidad: Comportamiento estable en los tres navegadores validados.
- UX y rendimiento: Navegación fluida pero con oportunidades de mejora en carga de imágenes y mensajería en acciones clave.

Impacto: La adopción de las recomendaciones reducirá defectos en producción, aumentará la confianza en releases, acelerará el ciclo de desarrollo y mejorará la experiencia del usuario.

------------------------------------------------------------

13. Trabajo futuro
- Implementar y validar bloqueo por intentos y recuperación de credenciales
- Añadir historial de contraseñas y verificación “misma actual”
- Optimizar imágenes y activar placeholders/skeletons
- Integrar CI/CD e informes automáticos
- Ampliar cobertura a accesibilidad y performance budgets
- Pruebas en dispositivos reales móviles y perfiles de red degradados

------------------------------------------------------------

14. Referencias
- Playwright Test – Documentation: https://playwright.dev/
- Node.js – Documentation: https://nodejs.org/
- OWASP Top 10 (Web Security): https://owasp.org/www-project-top-ten/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- WCAG 2.2 – W3C: https://www.w3.org/WAI/standards-guidelines/wcag/
- GitHub Actions – Docs: https://docs.github.com/actions
- Buggy Cars Rating (SUT): https://buggy.justtestit.org/

------------------------------------------------------------

15. Anexos

Anexo A. Casos de prueba (detalle)
Nota: Se listan los casos de prueba manuales tal como fueron ejecutados, incluyendo prioridad, precondiciones, datos de entrada, pasos, resultados esperados y estado. Los resultados con código ERRO-XX indican defecto.

AREA FUNCIONAL: REGISTRO DE USUARIO
1. CASO A1 (ALTA) – Verificar que el usuario pueda registrarse correctamente.
   Datos: Login: Marco@gmail.com; First Name: Marco; Last Name: Tulio; Password/Confirm: Marco123/
   Pasos: 1) Ir a /register 2) Completar registro 3) Click Register
   Esperado: Mensaje éxito “Registration is successful”
   Estado: APROBADO

2. CASO A2 (ALTA) – Validar mensajes de error cuando los campos están vacíos.
   Datos: Login: Marco@gmail.com; First Name: (en blanco); Last Name: Prueba; Password/Confirm: Marco123/
   Pasos: 1) /register 2) Completar 3) Dejar uno o más campos vacíos (espacio en blanco) 4) Register
   Esperado: Mensajes de error por campo requerido y validación en backend
   Resultado: ERRO-001

3. CASO A3 (ALTA) – Validar contraseñas iguales.
   Datos: Password: Test@up8; Confirm: Test@
   Pasos: 1) /register 2) Completar 3) Forzar mismatch 4) Register
   Esperado: “Passwords do not match”
   Estado: APROBADO

4. CASO A4 (ALTA) – Validar no crear usuario ya registrado.
   Datos: Login existente; Password: Test@up9
   Pasos: 1) /register 2) Usar login existente 3) Register
   Esperado: “Username already exists”
   Estado: APROBADO

5. CASO A5 (MEDIA) – Contraseña débil.
   Datos: Password abcde
   Pasos: 1) /register 2) Registrar con abcde 3) Register
   Esperado: “Password must meet complexity requirements”
   Estado: APROBADO

6. CASO A6 (MEDIA) – Caracteres especiales no válidos en username.
   Datos: Login: @@@user###
   Pasos: 1) /register 2) Usar @@@user### 3) Register
   Esperado: “Invalid characters”
   Resultado: ERRO-02

7. CASO A7 (BAJA) – Longitudes máximas username (60).
   Pasos: 1) /register 2) Username 60 chars 3) Register
   Esperado: Error o truncado
   Estado: APROBADO

8. CASO A8 (BAJA) – Espacios inicio/fin en username.
   Datos: “ Marco_test ”
   Pasos: 1) /register 2) Username con espacios 3) Register
   Esperado: Trim o error
   Estado: APROBADO

AREA FUNCIONAL: INICIO / CIERRE DE SESIÓN
1. CASO B1 (ALTA) – Usuario válido
   Datos: Login: Marco@gmail.com; Password: Test@up9
   Pasos: 1) Home 2) Login 3) Click Login
   Esperado: Acceso exitoso
   Estado: APROBADO

2. CASO B2 (ALTA) – Credenciales inválidas
   Datos: Login: falso@gmail.com; Password: Test@up9
   Pasos: 1) Home 2) Login 3) Click Login
   Esperado: “Invalid username or password”
   Estado: APROBADO

3. CASO B3 (MEDIA) – Logout con sesión activa
   Pasos: 1) Home 2) Iniciar sesión 3) Click Login 4) Logout
   Esperado: Cierra sesión
   Estado: APROBADO

4. CASO B4 (MEDIA) – Case sensitivity
   Datos: Usuario existente
   Esperado: Diferenciar mayúsculas/minúsculas (según especificación)
   Estado: APROBADO

5. CASO B5 (MEDIA) – Sesión iniciada hace 15–30 min
   Pasos: 1) Login 2) Esperar 15–30 min
   Esperado: Redirigir a login o “sesión expirada”
   Resultado: ERRO-03

6. CASO B6 (ALTA) – Olvido de credenciales
   Pasos: 1) Buscar recuperación credenciales
   Esperado: Enlace visible de recuperación
   Resultado: ERRO-04

7. CASO B7 (ALTA) – Múltiples intentos (≥15) con credenciales incorrectas
   Esperado: Bloqueo temporal / captcha
   Resultado: ERRO-05

AREA FUNCIONAL: ACTUALIZAR PERFIL DE USUARIO
1. CASO C1 (MEDIA) – Cambiar First Name
   Esperado: Cambios guardados
   Estado: APROBADO

2. CASO C2 (BAJA) – First Name “@@@” o >100 chars
   Esperado: Mensaje de validación
   Resultado: ERRO-06

3. CASO C3 (MEDIA) – Last Name vacío
   Esperado: “Field required”
   Estado: APROBADO

4. CASO C4 (MEDIA) – Gender editable como texto
   Esperado: Selector bloqueado Male/Female
   Resultado: ERRO-07

5. CASO C5 (MEDIA) – Age con texto “23 años”
   Esperado: Solo numérico, mensaje de validación
   Resultado: ERRO-08

6. CASO C6 (MEDIA) – Address alfanumérica y símbolos
   Esperado: Aceptado
   Estado: APROBADO

7. CASO C7 (MEDIA) – Phone con valores numéricos y símbolos válidos
   Esperado: Aceptado
   Estado: APROBADO

AREA FUNCIONAL: CAMBIO DE CONTRASEÑA
1. CASO D1 (ALTA) – Cambio válido
   Esperado: Nueva contraseña funciona
   Estado: APROBADO

2. CASO D2–D4 (MEDIA) – Contraseñas débiles/insuficientes
   Esperado: Error
   Estado: APROBADO

5. CASO D5 (MEDIA) – Reutilizar contraseña anterior
   Esperado: Bloqueo
   Resultado: ERRO-09

6. CASO D6 (MEDIA) – Igual a contraseña actual
   Esperado: Bloqueo
   Resultado: ERRO-10

AREA FUNCIONAL: VOTAR POR AUTOS
1. CASO E1 (ALTA) – Voto válido
   Esperado: “Thank you for your vote!”
   Estado: APROBADO

2. CASO E2 (MEDIA) – Voto duplicado al mismo modelo
   Esperado: “You have already voted for this car!”
   Estado: APROBADO

3. CASO E3 (ALTA) – Usuario no logueado
   Esperado: Redirigir a Login / mensaje
   Estado: APROBADO

4. CASO E4 (MEDIA) – Modelo inexistente (/model/99999)
   Esperado: Mensaje claro o redirección, no “loading” indefinido
   Resultado: ERRO-11

AREA FUNCIONAL: COMENTARIOS EN MODELOS
1. CASO F1 (MEDIA) – Comentario “Excelente diseño”
   Esperado: Publicado
   Estado: APROBADO

2. CASO F2 (BAJA) – Voto sin comentario
   Esperado: Mensaje claro de validación o confirmación
   Resultado: ERRO-12

3. CASO F3 (MEDIA) – Texto largo
   Esperado: Error de longitud
   Estado: APROBADO

4. CASO F4 (ALTA) – XSS en comentario
   Esperado: No ejecuta, texto plano
   Estado: APROBADO

AREA FUNCIONAL: NAVEGACIÓN Y CONTENIDO
1. CASO G1 (ALTA) – Navegación general
   Esperado: Modelos cargan correctamente
   Estado: APROBADO

2. CASO G2 (ALTA) – Rendimiento de imágenes/íconos
   Esperado: Carga inmediata/<1s, caché/precarga, loaders
   Resultado: ERRO-13

3. CASO G3 (ALTA) – Errores 404 e imágenes faltantes
   Esperado: Sin 404 ni imágenes faltantes
   Estado: APROBADO

4. CASO G4 (BAJA) – Persistencia de sesión tras refresh
   Esperado: Sesión permanece activa
   Estado: APROBADO

AREA FUNCIONAL: ERRORES Y VALIDACIONES
1. CASO H1 (ALTA) – XSS genérico
   Esperado: No ejecuta código
   Estado: APROBADO

2. CASO H2 (ALTA) – SQLi genérico
   Esperado: Bloqueo/errores
   Estado: APROBADO

Anexo B. Bitácora de defectos (ERRO-001 a ERRO-013)
Se resumen los reportes tal como fueron elaborados:
- ERRO-01: Formulario permite envío con campos vacíos (Alta)
- ERRO-02: Username acepta caracteres especiales no válidos (Media)
- ERRO-03: Sesión no expira tras 30 min de inactividad (Media)
- ERRO-04: Falta enlace “Olvidé mi contraseña/usuario” (Alta)
- ERRO-05: Sin bloqueo tras múltiples intentos de login (Alta)
- ERRO-06: Validaciones de longitud/tipo de datos insuficientes (Baja)
- ERRO-07: Gender permite texto libre (Media)
- ERRO-08: Edad acepta texto no numérico (Media)
- ERRO-09: Permite reutilizar contraseña anterior (Media)
- ERRO-10: Permite usar la misma contraseña actual (Media)
- ERRO-11: Modelo inexistente deja página cargando indefinidamente (Media)
- ERRO-12: Voto sin comentario y sin mensaje de confirmación/validación (Baja)
- ERRO-13: Retraso en carga de imágenes e íconos (Alta)

Anexo C. Evidencias y comandos
Comandos rápidos:
```bash
# Ejecutar todas las pruebas
npx playwright test

# Ver reporte HTML
npx playwright show-report

# Pruebas específicas
npx playwright test login.spec.js
```

Anexo D. Extractos de configuración (Playwright)
- testDir: ./tests
- fullParallel: true
- retries (CI): 2
- reporter: html
- projects: chromium, firefox, webkit
- trace: on-first-retry

------------------------------------------------------------

Firmado:
Marco Tulio
Aseguramiento de la Calidad del Software | Octubre 2025
