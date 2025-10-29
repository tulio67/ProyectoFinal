# CONFIGURACIÓN DEL PROYECTO - ASEGURAMIENTO DE CALIDAD

## INFORMACIÓN DEL ESTUDIANTE
- **Nombre:** Marco Tulio
- **Curso:** Aseguramiento de la Calidad del Software
- **Institución:** [Nombre de la Institución]
- **Fecha de Entrega:** Octubre 2025

## CREDENCIALES DE PRUEBA
- **Email de prueba:** Marco@gmail.com
- **Contraseña:** Marco123/
- **Primer Nombre:** Marco
- **Segundo Nombre:** Tulio

## URLs IMPORTANTES
- **Aplicación bajo prueba:** https://buggy.justtestit.org/
- **Repositorio GitHub:** https://github.com/tulio67/ProyectoFinal
- **Documentación Playwright:** https://playwright.dev/

## COMANDOS FRECUENTES

### Instalación
```bash
npm install
npx playwright install
```

### Ejecución de pruebas
```bash
# Todas las pruebas
npx playwright test

# Pruebas específicas por categoría
npx playwright test login.spec.js              # Autenticación
npx playwright test register.spec.js           # Registro
npx playwright test navigation.spec.js         # Navegación
npx playwright test form-validation.spec.js    # Validación de formularios
npx playwright test security-tests.spec.js     # Pruebas de seguridad
npx playwright test buggy-features.spec.js     # Funcionalidades específicas

# Por navegador
npx playwright test --project=chromium         # Solo Chrome
npx playwright test --project=firefox          # Solo Firefox
npx playwright test --project=webkit           # Solo Safari

# Modos especiales
npx playwright test --debug                    # Modo debug
npx playwright test --headed                   # Con navegador visible
npx playwright test --reporter=line            # Reporte en línea
npx playwright test --reporter=html            # Reporte HTML
```

### Reportes
```bash
npx playwright show-report                     # Abrir reporte HTML
```

## ESTRUCTURA DE ARCHIVOS GENERADOS

### Archivos de Documentación
- `README.md` - Documentación principal del proyecto
- `INFORME_TECNICO.md` - Informe técnico completo y detallado
- `RESUMEN_EJECUTIVO.md` - Resumen ejecutivo para presentaciones
- `PROJECT_CONFIG.md` - Este archivo de configuración

### Archivos de Código
- `package.json` - Configuración de dependencias Node.js
- `playwright.config.js` - Configuración del framework Playwright

### Archivos de Pruebas (Directorio /tests/)
- `example.spec.js` - Pruebas básicas de ejemplo
- `login.spec.js` - Pruebas de autenticación y login
- `register.spec.js` - Pruebas de registro de usuarios
- `navigation.spec.js` - Pruebas de navegación web
- `form-validation.spec.js` - Validaciones de formularios
- `security-tests.spec.js` - Pruebas de seguridad
- `buggy-features.spec.js` - Funcionalidades específicas de la app

### Archivos Generados por Playwright
- `/test-results/` - Resultados de ejecución de pruebas
- `/playwright-report/` - Reportes HTML generados

## MÉTRICAS DEL PROYECTO

### Estadísticas de Código
- **Archivos de prueba:** 7
- **Casos de prueba:** 93
- **Líneas de código:** ~1,500+
- **Funciones de prueba:** 31

### Cobertura de Funcionalidades
- ✅ Autenticación y autorización
- ✅ Registro de nuevos usuarios
- ✅ Navegación entre páginas
- ✅ Validación de formularios
- ✅ Seguridad contra vulnerabilidades
- ✅ Funcionalidades específicas de la aplicación

### Navegadores Probados
- ✅ Chromium (Chrome/Edge)
- ✅ Firefox
- ✅ WebKit (Safari)

## TECNOLOGÍAS Y VERSIONES

### Dependencias Principales
```json
{
  "@playwright/test": "^1.56.1",
  "@types/node": "^24.9.1"
}
```

### Entorno de Desarrollo
- **Node.js:** v22.12.0
- **npm:** Latest
- **Sistema Operativo:** Windows
- **Terminal:** PowerShell

## OBJETIVOS DE APRENDIZAJE CUMPLIDOS

### Técnicos
1. ✅ Implementación de framework de pruebas automatizadas
2. ✅ Desarrollo de casos de prueba comprehensivos
3. ✅ Validación de seguridad de aplicaciones web
4. ✅ Pruebas cross-browser
5. ✅ Manejo de selectores y elementos web
6. ✅ Implementación de pruebas asíncronas

### Conceptuales
1. ✅ Principios de aseguramiento de calidad
2. ✅ Metodologías de testing
3. ✅ Identificación de vulnerabilidades
4. ✅ Documentación técnica
5. ✅ Análisis de resultados
6. ✅ Recomendaciones de mejora

### Profesionales
1. ✅ Uso de herramientas modernas de testing
2. ✅ Control de versiones con Git
3. ✅ Documentación profesional
4. ✅ Análisis crítico de resultados
5. ✅ Comunicación técnica efectiva

## ENTREGABLES DEL PROYECTO

### Documentación
- [x] README.md profesional
- [x] Informe técnico completo
- [x] Resumen ejecutivo
- [x] Configuración del proyecto

### Código
- [x] Framework de pruebas funcional
- [x] 93 casos de prueba implementados
- [x] Configuración de Playwright optimizada
- [x] Código bien documentado y comentado

### Resultados
- [x] Ejecución exitosa de pruebas
- [x] Reportes HTML generados
- [x] Análisis de fallos y recomendaciones
- [x] Validación de seguridad completada

## NOTAS ADICIONALES

### Consideraciones Importantes
- Las credenciales utilizadas son específicas para el usuario Marco Tulio
- La aplicación buggy.justtestit.org es una plataforma de pruebas oficial
- Algunos fallos son esperados debido a la naturaleza "buggy" de la aplicación
- El proyecto demuestra capacidades reales de testing, no solo casos ideales

### Posibles Mejoras Futuras
1. Integración con pipeline CI/CD
2. Pruebas de rendimiento y carga
3. Pruebas de accesibilidad (WCAG)
4. Cobertura de pruebas móviles nativas
5. Integración con herramientas de monitoreo

---

**Marco Tulio**  
*Aseguramiento de la Calidad del Software*  
*Octubre 2025*