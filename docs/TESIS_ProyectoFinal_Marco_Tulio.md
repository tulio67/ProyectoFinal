<!-- ============================= -->
<!-- CARÁTULA (formato ejemplo)   -->
<!-- ============================= -->

<p style="text-align:center; line-height:1.5; font-size:12pt;">
  <strong>Universidad Mariano Galvez de Guatemala</strong><br/>
  <span>Ingeniería En Sistemas de Información</span><br/>
  <span>Sede Chiquimulilla</span>
</p>

<p style="margin: 60pt 0;"></p>

<h1 style="text-align:center; font-size:20pt; margin:0;">
  Proyecto Final – Aseguramiento de la Calidad del Software
</h1>
<h3 style="text-align:center; font-size:14pt; margin-top:6pt; font-weight:normal;">
  Pruebas manuales y automatizadas sobre Buggy Cars Rating (https://buggy.justtestit.org/) con Playwright
</h3>

<p style="margin: 72pt 0;"></p>

<p style="font-size:12pt; line-height:1.5;">
  <strong>Estudiante:</strong> Marco Tulio Lara Salazar<br/>
  <strong>Carnet:</strong> 1790-21-16467
</p>

<p style="margin: 72pt 0;"></p>

<p style="text-align:right; font-size:12pt;">
  Chiquimulilla, agosto de 2025
</p>

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

<!-- ============================= -->
<!-- CUERPO DEL INFORME            -->
<!-- ============================= -->

# Proyecto Final – Aseguramiento de la Calidad del Software
Pruebas manuales y automatizadas sobre Buggy Cars Rating (https://buggy.justtestit.org/) con Playwright

Autor: Marco Tulio Lara Salazar  
Curso: Aseguramiento de la Calidad del Software  
Fecha: Octubre 2025  
Repositorio: https://github.com/tulio67/ProyectoFinal  
Branch por defecto: master  
Idioma principal: JavaScript

---

Tabla de contenido (se genera con --toc)

---

## 1. Resumen ejecutivo
[Contenido ampliado con síntesis de objetivos, alcance, metodología, hallazgos, métricas y recomendaciones clave. Incluye 3–4 párrafos desarrollados.]

## 2. Abstract (English)
[Versión en inglés del resumen; 2–3 párrafos completos.]

## 3. Introducción
[1 página completa: contexto, motivación, objetivos generales/específicos, valor del estudio y organización del documento.]

## 4. Marco teórico y estado del arte
- Verificación vs validación; técnicas de diseño de pruebas (particiones, límites, tablas de decisión).
- OWASP: amenazas y controles; autenticación defensiva; gestión de sesión.
- Automatización E2E: razones para usar Playwright vs alternativas.
- Métricas de calidad (técnicas y de UX).

## 5. Metodología y diseño del estudio
- Enfoque mixto (manual + automatizado), criterios de entrada/salida, control de sesgos.
- Alcance funcional y no funcional; navegadores y SO utilizados.
- Datos de prueba (válidos, inválidos, maliciosos controlados).
- Ciclo PDCA y evidencias recopiladas.

## 6. Arquitectura técnica de pruebas y configuración
- Estructura del repositorio, herramientas y versiones.
- Configuración Playwright: paralelismo, retries, reporter, trace.
- Selectores robustos (data-testid), aislamiento de contexto y limpieza de estado.
- Integración en CI (concepto) y flujo de exportación del DOCX.

## 7. Plan de pruebas, cobertura y trazabilidad
- Objetivos por módulo; matriz requisito→casos (muestra).
- Criterios de aceptación transversales (mensajes, códigos HTTP, validaciones simétricas).
- Cobertura por categoría y navegadores.

## 8. Casuística ampliada y criterios de aceptación
- Username: trimming, unicidad post-normalización, listas denegadas.
- Contraseñas: ≥10 chars, mezcla de tipos, historial y no igual a la actual.
- Sesión: expiración 15–30 min, logout invalida.
- Votación/Comentarios: no duplicidad, límites, XSS bloqueado.
- Navegación: fallback 404 claro y sin “loading” indefinido.

## 9. Seguridad y cumplimiento (OWASP)
- Validación/saneamiento “whitelist”; codificación de salida.
- Autenticación defensiva: rate limiting por IP/usuario, backoff y captcha progresivo.
- Recuperación segura de contraseña (token de un solo uso, expiración, hashing).
- Headers de seguridad recomendados (CSP, HSTS, XFO, etc.).

## 10. Rendimiento percibido y UX
- Observación: retrasos en imágenes/íconos (ERRO‑13).
- Acciones: WebP/AVIF, lazy‑loading, placeholders/skeletons, precarga.
- Métricas guía: LCP < 2.5s, CLS < 0.1; instrumentación con Lighthouse/RUM.
- Estrategias de caché y CDN.

## 11. Resultados y análisis estadístico
- 93 tests, 75 passed (80.6%), distribución por categoría y navegador.
- Tendencias y causas probables de fallos.
- Conclusiones por área (seguridad, validaciones, UX, navegación).

## 12. Estudio comparativo de herramientas
- Selenium vs Playwright: ventajas/compromisos, justificación de elección.

## 13. Diseño detallado de casos (muestras)
- Registro, Autenticación, Perfil, Votación/Comentarios, Navegación.
- Ejemplos de entradas, resultados esperados y criterios de aceptación.

## 14. Gestión de riesgos y amenazas a la validez
- Riesgos priorizados (R1–R4) con impacto y mitigaciones.
- Amenazas a la validez (entorno, medición, falta de logs) y cómo se mitigaron.

## 15. Recomendaciones y hoja de ruta
- Corto, mediano y largo plazo con acciones y KPIs (≥95% éxito, LCP P75 < 2.5s, MTTR P1 < 24h).

## 16. Conclusiones
[1 página completa con síntesis crítica y ruta de adopción.]

## 17. Trabajo futuro
- Accesibilidad (WCAG), performance budgets, RUM, cobertura móvil, i18n, test impact analysis.

## 18. Glosario
- LCP, TTI, RUM, TTL, CSP y otros términos clave.

## 19. Referencias
- Playwright, Node.js, OWASP Top 10 y ASVS, WCAG 2.2, Web.dev Core Web Vitals, GitHub Actions.

## 20. Anexos
### Anexo A. Casos de prueba (resumen ampliado)
[Listado extenso de casos por módulo con datos/criterios.]
### Anexo B. Bitácora de defectos (ERRO‑001 a ERRO‑013)
[Resumen de cada defecto: descripción, pasos, esperado/actual, prioridad.]
### Anexo C. Comandos útiles
```bash
npx playwright test
npx playwright show-report
npx playwright test login.spec.js
```
### Anexo D. Configuración Playwright (extractos)
- testDir: ./tests; fullParallel: true; retries: 2; reporter: html; projects: chromium/firefox/webkit; trace: on-first-retry.

---

Firmado:  
Marco Tulio Lara Salazar – Octubre 2025
