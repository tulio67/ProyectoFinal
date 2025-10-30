<!-- ============================= -->
<!-- CARÁTULA (formato institucional) -->
<!-- ============================= -->

<p style="text-align:center; line-height:1.5; font-size:12pt;">
  <strong>Universidad Mariano Gálvez de Guatemala</strong><br/>
  <span>Ingeniería en Sistemas de Información</span><br/>
  <span>Sede Chiquimulilla</span>
</p>

<p style="margin: 60pt 0;"></p>

<h1 style="text-align:center; font-size:20pt; margin:0;">
  Evaluación Integral de Calidad de Software
</h1>
<h3 style="text-align:center; font-size:14pt; margin-top:6pt; font-weight:normal;">
  Validaciones funcionales, seguridad aplicada y experiencia de usuario en Buggy Cars Rating con Playwright
</h3>

<p style="margin: 72pt 0;"></p>

<p style="font-size:12pt; line-height:1.6;">
  <strong>Estudiante:</strong> Anthony Grijalva
</p>

<p style="margin: 72pt 0;"></p>

<p style="text-align:right; font-size:12pt;">
  Chiquimulilla, octubre de 2025
</p>

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

<!-- ============================= -->
<!-- CUERPO DEL INFORME            -->
<!-- ============================= -->

# Evaluación Integral de Calidad de Software
Validaciones funcionales, seguridad aplicada y experiencia de usuario en Buggy Cars Rating con Playwright

Autor: Anthony Grijalva  
Asignatura: Aseguramiento de la Calidad del Software  
Fecha: Octubre 2025

---

Tabla de contenido (se generará automáticamente con --toc)

---

## 1. Resumen ejecutivo

Este documento presenta una evaluación completa de la aplicación web “Buggy Cars Rating”, enfocada en tres pilares: corrección funcional, seguridad de autenticación/gestión de sesiones y experiencia de usuario con énfasis en rendimiento percibido. La validación combinó pruebas manuales estructuradas y exploratorias con una suite de automatización E2E en Playwright que se ejecuta en los navegadores principales (Chromium, Firefox y WebKit).

Cobertura: registro de usuario, inicio/cierre de sesión, edición de perfil, votación/comentarios y navegación general. El enfoque reveló inconsistencias entre validación cliente/servidor, ausencia de mitigaciones efectivas ante intentos reiterados de acceso (rate limiting y captcha), políticas de expiración de sesión perfectibles y oportunidades claras para acelerar la carga de medios (imágenes/íconos) con formatos modernos y prácticas de caché.

Métricas destacadas:
- 96 casos automatizados.
- 78 aprobados (81.25% de éxito global).
- Evidencias: reportes HTML y trazas activadas en fallos.

Recomendaciones principales:
- Aplicar autenticación defensiva (bloqueo por intentos, backoff y captcha progresivo).
- Uniformar validaciones en servidor; normalizar y sanear entradas.
- Optimizar medios estáticos (WebP/AVIF, lazy-loading, placeholders) y políticas de caché/CDN.

---

## 2. Abstract (English)

This report delivers a comprehensive assessment of the “Buggy Cars Rating” web application, focusing on functional correctness, secure authentication and session management, and user experience with perceived performance. We combined structured and exploratory manual testing with a Playwright end-to-end suite across Chromium, Firefox, and WebKit. Coverage includes registration, login/logout, profile updates, rating/comments, and overall navigation.

Key findings include inconsistent client/server validations, lack of robust brute-force mitigation, session timeouts that could be strengthened, and optimization opportunities for image/icon loading. The automation suite executed 96 tests with 78 passes (81.25%), generating HTML reports and traces for diagnostics. We recommend enforcing defensive authentication, consolidating server-side validations, and accelerating static assets via modern formats, lazy-loading, placeholders, and CDN-backed caching.

---

## 3. Introducción

Asegurar la calidad de un sistema web implica verificar no solo que “funcione”, sino que lo haga de forma consistente, segura y comprensible para el usuario. En esta evaluación se estudia “Buggy Cars Rating” como un caso representativo donde conviven flujos básicos —registro, autenticación y perfil— con funcionalidades sociales —votación y comentarios—, idóneos para observar la relación entre reglas de negocio, estado de sesión y feedback de interfaz.

Motivación y propósito:
- Obtener evidencia objetiva sobre el estado actual de calidad.
- Proponer mejoras concretas y priorizadas por impacto/esfuerzo.
- Dejar un esquema reproducible de pruebas que facilite regresiones y mantenimiento.

Enfoque adoptado:
- Pruebas manuales para explorar bordes de UX, mensajes y reglas de negocio.
- Automatización E2E con Playwright para repetibilidad, paralelización y cobertura multi‑navegador, con reportes y trazas que aceleran el diagnóstico.

---

## 4. Fundamentos y revisión breve de literatura

- Verificación vs validación: conformidad técnica vs adecuación a la necesidad.
- Diseño de pruebas funcionales: particiones equivalentes, valores límite, tablas de decisión y casos negativos (rutas inexistentes, entradas maliciosas controladas).
- Seguridad (OWASP) aplicada: validación/saneamiento, autenticación robusta, gestión de sesión, headers de seguridad y registro de eventos.
- Automatización E2E (Playwright): aislamiento por contexto, selectores robustos (data-testid), soporte nativo de múltiples motores y trazabilidad integrada.
- Métricas orientadas a calidad: éxito de pruebas, densidad de defectos, flakiness, cobertura por módulo, y señales de UX (LCP, CLS).

---

## 5. Diseño metodológico

- Estrategia mixta:
  - Manual: casos por módulo y exploración dirigida por riesgos de seguridad/UX.
  - Automatizada: batería Playwright con reporter HTML y trazas on‑first‑retry.
- Entornos:
  - Windows 11 y macOS reciente; navegadores Chromium, Firefox y WebKit.
- Datos de prueba:
  - Combinación de entradas válidas/ inválidas y patrones maliciosos controlados (XSS/SQLi).
- Criterios de entrada/salida:
  - Entrada: SUT disponible, datos definidos y conectividad estable.
  - Salida: ejecución completa/justificada y consolidado de hallazgos con evidencias.

---

## 6. Entorno técnico y arquitectura de pruebas

- Organización del repositorio:
  - Documentación (informes), automatización (tests, config) y utilidades.
- Configuración de Playwright:
  - Paralelismo habilitado, reintentos en CI, reporte HTML y trazas on‑first‑retry.
- Selectores:
  - Preferencia por data-testid; evitar selectores frágiles por texto o jerarquías profundas.
- Aislamiento:
  - Contextos limpios por caso y manejo explícito del estado de sesión.

Ejemplo orientativo:
```js
test('autenticación válida muestra opciones de perfil', async ({ page }) => {
  await page.goto('https://buggy.justtestit.org/');
  await page.getByLabel('Login').fill('usuario@prueba.com');
  await page.getByLabel('Password').fill('ClaveSegura!9');
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page.getByText('Logout')).toBeVisible();
});
```

---

## 7. Cobertura, criterios y trazabilidad

Objetivos:
- Asegurar reglas de negocio, validar defensas de autenticación y mantener mensajería clara.

Módulos cubiertos:
- Registro, Login/Logout, Perfil, Votación/Comentarios y Navegación.

Criterios transversales:
- Validaciones espejo cliente/servidor, códigos HTTP adecuados, estados de carga sin bloqueos.

Trazabilidad (muestra):
- R-VAL-001 (campos obligatorios/formatos) → Casos de Registro.
- R-AUT-002 (intentos reiterados) → Casos de Login.
- R-SEC-003 (XSS/SQLi bloqueados) → Casos de Comentarios.
- R-UX-004 (tiempos de imagen/feedback) → Navegación/Medios.

---

## 8. Escenarios de prueba extendidos

- Registro:
  - Longitudes y normalización; contraseñas fuertes; duplicidad de usuario; caracteres no permitidos.
- Autenticación:
  - Credenciales válidas/ inválidas; múltiples intentos; expiración por inactividad; logout forzado.
- Perfil:
  - Tipado en campos numéricos y listas; límites; mensajes por campo.
- Votación/Comentarios:
  - Confirmaciones explícitas; no duplicidad; límites de longitud; neutralización de scripts.
- Navegación:
  - Fallbacks claros ante rutas y recursos inexistentes (404 no intrusivos).

---

## 9. Seguridad aplicada y cumplimiento

- Validación/saneamiento:
  - Listas blancas por campo, normalización de espacios/casos y codificación de salida.
- Autenticación defensiva:
  - Rate limiting por usuario/IP, backoff progresivo y captcha a partir de umbrales.
  - Recuperación segura de credenciales con tokens efímeros y hashing robusto.
- Cabeceras de seguridad sugeridas:
  - CSP, HSTS, X‑Content‑Type‑Options, X‑Frame‑Options y Referrer‑Policy.
- Políticas de contraseñas:
  - Complejidad mínima, historial y prohibición de reutilización/igual a la actual.

---

## 10. Experiencia de usuario y desempeño percibido

- Observaciones:
  - Cargas perceptibles en imágenes/íconos y ausencia de placeholders.
- Acciones propuestas:
  - Uso de WebP/AVIF; lazy-loading; skeletons; precarga de recursos críticos.
- Medición:
  - Umbrales guía (LCP < 2.5 s; CLS < 0.1) y monitoreo con Lighthouse/RUM.
- Caché/CDN:
  - Políticas de Cache-Control/ETag y distribución en edge.

---

## 11. Resultados y análisis

- Resultados de automatización:
  - 96 casos; 78 aprobados; 18 con hallazgos; flakiness bajo control.
- Tendencias:
  - Fallos concentrados en validaciones no simétricas y expiración de sesión.
- Impacto:
  - Riesgo de abuso por intentos repetidos sin freno; experiencia degradada por medios no optimizados.

---

## 12. Discusión de hallazgos y limitaciones

- Hallazgos clave:
  - Necesidad de defensas de autenticación y normalización en servidor.
  - Oportunidades de UX al mejorar estados de carga y manejo de errores.
- Limitaciones:
  - Sin telemetría de backend ni pruebas de carga/estrés; inferencias basadas en observación y herramientas ligeras.
- Implicaciones:
  - Correcciones priorizadas reducirán incidentes y regresiones en releases.

---

## 13. Hoja de ruta de mejoras

- Corto plazo (0–2 semanas):
  - Rate limiting + captcha; validaciones server-side; mensajes de error consistentes.
- Mediano plazo (2–6 semanas):
  - Expiración estricta de sesión; historial de contraseñas; rotación de tokens.
  - Optimización de medios y CDN.
- Largo plazo:
  - Integración de auditorías automáticas (Lighthouse/axe) y tableros de observabilidad.

KPIs sugeridos:
- ≥ 95% de éxito en suites críticas.
- Cero incidentes por fuerza bruta tras bloqueo/captcha.
- LCP P75 < 2.5 s en vistas principales.
- MTTR P1 < 24 h; reducción sostenida de reabiertos.

---

## 14. Conclusiones

La evaluación confirma una base funcional aceptable y defensas efectivas ante inyección/XSS en los escenarios medidos, pero revela brechas que conviene atender con prioridad: mitigación ante intentos reiterados de acceso, expiración de sesión y consistencia de validaciones en servidor. En UX, la optimización de recursos visuales y la claridad de estados de carga ofrecen mejoras rápidas y de alto impacto. La adopción del plan propuesto, con métricas y evidencias trazables, elevará la seguridad, la confiabilidad y la satisfacción del usuario final.

---

## 15. Trabajo futuro

- Accesibilidad (WCAG) y presupuestos de rendimiento por vista.
- RUM en producción y alarmas de Core Web Vitals.
- Pruebas móviles en dispositivos reales y redes degradadas.
- Internacionalización y pruebas de contenido multilenguaje.
- Priorización por impacto de cambio (test impact analysis).

---

## 16. Glosario

- LCP: Largest Contentful Paint.  
- CLS: Cumulative Layout Shift.  
- TTI: Time to Interactive.  
- RUM: Real User Monitoring.  
- TTL: Tiempo de vida de sesión/cookie.  
- CSP: Content Security Policy.

---

## 17. Referencias

- Playwright Test – Documentation: https://playwright.dev/  
- Node.js – Documentation: https://nodejs.org/  
- OWASP Top 10: https://owasp.org/www-project-top-ten/  
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/  
- WCAG 2.2 – W3C: https://www.w3.org/WAI/standards-guidelines/wcag/  
- Web.dev (Core Web Vitals): https://web.dev/vitals/  
- GitHub Actions – Docs: https://docs.github.com/actions  
- Buggy Cars Rating (SUT): https://buggy.justtestit.org/

---

## 18. Anexos

### Anexo A. Casos de prueba (resumen)
- Registro: obligatoriedad, formatos, longitudes, normalización, duplicidad, contraseñas fuertes.  
- Autenticación: válidas/ inválidas, múltiples intentos, expiración, logout.  
- Perfil: tipado, límites y mensajes por campo.  
- Votación/Comentarios: confirmaciones, no duplicidad, límites y neutralización de scripts.  
- Navegación: rutas/recursos inexistentes con fallbacks claros.

### Anexo B. Bitácora de hallazgos (ejemplos)
- AH-01: Validación de campos inconsistente cliente/servidor.  
- AH-02: Ausencia de rate limiting en login.  
- AH-03: Expiración por inactividad no estricta.  
- AH-04: Carga lenta de medios sin placeholders.  
- AH-05: Mensajería de error perfectible en rutas inexistentes.

### Anexo C. Comandos útiles
```bash
# Ejecutar toda la suite
npx playwright test

# Abrir el reporte HTML
npx playwright show-report

# Ejecutar un archivo específico
npx playwright test auth.spec.js
```

### Anexo D. Configuración Playwright (extractos)
- Paralelismo habilitado; reintentos en CI (2); reporter HTML; trazas on‑first‑retry.  
- Proyectos: chromium, firefox, webkit; selectores data‑testid.  

---

Firmado:  
Anthony Grijalva – Octubre 2025
