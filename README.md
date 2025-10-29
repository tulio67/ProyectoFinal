# 🚗 Buggy Cars Testing - Proyecto de Asegu### 📁 Estructura de Directorios
```
proyecto-final-aseguramiento/
├── 📄 package.json                 # Configuración de dependencias
├── ⚙️ playwright.config.js         # Configuración de Playwright
├── 📋 INFORME_TECNICO.md           # Informe técnico completo
├── 📊 RESUMEN_EJECUTIVO.md         # Resumen ejecutivo
├── 📖 README.md                    # Este archivo
└── tests/                         # 🧪 Directorio de pruebas
    ├── 🚬 smoke.spec.js            # Pruebas de smoke (críticas)
    ├── 🔐 login.spec.js            # Pruebas de autenticación
    ├── 📝 register.spec.js         # Pruebas de registro
    ├── 🧭 navigation.spec.js       # Pruebas de navegación
    ├── ✅ form-validation.spec.js  # Validaciones de formularios
    ├── 🛡️ security-tests.spec.js   # Pruebas de seguridad
    ├── 🚗 buggy-features.spec.js   # Funcionalidades específicas
    └── 📚 example.spec.js          # Pruebas de ejemplo
```amiento de Calidad

[![Playwright Tests](https://img.shields.io/badge/Tests-93%20Total-blue)](https://github.com/tulio67/ProyectoFinal)
[![Success Rate](https://img.shields.io/badge/Success%20Rate-80.6%25-green)](https://github.com/tulio67/ProyectoFinal)
[![Browsers](https://img.shields.io/badge/Browsers-Chrome%20%7C%20Firefox%20%7C%20Safari-orange)](https://playwright.dev/)

Framework completo de pruebas automatizadas para validar la calidad del software de la aplicación **Buggy Cars Rating**. Implementado con Playwright para asegurar funcionalidad, seguridad y compatibilidad cross-browser.

## 📋 Tabla de Contenidos
- [🎯 Objetivo](#-objetivo)
- [🛠️ Tecnologías](#️-tecnologías)
- [📁 Estructura del Proyecto](#-estructura-del-proyecto)
- [🚀 Instalación y Ejecución](#-instalación-y-ejecución)
- [🧪 Tipos de Pruebas](#-tipos-de-pruebas)
- [📊 Resultados](#-resultados)
- [🛡️ Validaciones de Seguridad](#️-validaciones-de-seguridad)
- [📖 Documentación](#-documentación)
- [👨‍💻 Autor](#-autor)

## 🎯 Objetivo

Implementar un conjunto completo de pruebas automatizadas que validen:
- ✅ Funcionalidades críticas de autenticación
- ✅ Procesos de registro de usuarios
- ✅ Navegación y experiencia de usuario
- ✅ Validaciones de formularios
- ✅ Seguridad contra vulnerabilidades comunes
- ✅ Funcionalidades específicas de la aplicación

## 🛠️ Tecnologías

| Tecnología | Versión | Propósito |
|-----------|---------|-----------|
| **Playwright** | v1.56.1 | Framework de pruebas automatizadas |
| **Node.js** | v22.12.0 | Entorno de ejecución JavaScript |
| **JavaScript** | ES6+ | Lenguaje de programación |
| **Git** | Latest | Control de versiones |

### Navegadores Soportados
- 🟢 **Chromium** (Chrome/Edge)
- 🟠 **Firefox** 
- 🔵 **WebKit** (Safari)

## 📁 Estructura del Proyecto

```
proyecto-final-aseguramiento/
├── 📄 package.json                 # Configuración de dependencias
├── ⚙️ playwright.config.js         # Configuración de Playwright
├── 📋 INFORME_TECNICO.md           # Informe técnico completo
├── 📊 RESUMEN_EJECUTIVO.md         # Resumen ejecutivo
├── 📖 README.md                    # Este archivo
└── tests/                         # 🧪 Directorio de pruebas
    ├── 🔐 login.spec.js            # Pruebas de autenticación
    ├── 📝 register.spec.js         # Pruebas de registro
    ├── 🧭 navigation.spec.js       # Pruebas de navegación
    ├── ✅ form-validation.spec.js  # Validaciones de formularios
    ├── 🛡️ security-tests.spec.js   # Pruebas de seguridad
    ├── 🚗 buggy-features.spec.js   # Funcionalidades específicas
    └── 📚 example.spec.js          # Pruebas de ejemplo
```

## 🚀 Instalación y Ejecución

### Prerrequisitos
- Node.js (v16 o superior)
- npm o yarn
- Git

### 1. Clonar el repositorio
```bash
git clone https://github.com/tulio67/ProyectoFinal.git
cd ProyectoFinal
```

### 2. Instalar dependencias
```bash
npm install
```

### 3. Instalar navegadores de Playwright
```bash
npx playwright install
```

### 4. Ejecutar pruebas

#### Todas las pruebas
```bash
npx playwright test
```

#### Pruebas específicas
```bash
npx playwright test smoke.spec.js      # Pruebas de smoke (críticas)
npx playwright test login.spec.js      # Solo autenticación
npx playwright test register.spec.js   # Solo registro
npx playwright test security-tests.spec.js  # Solo seguridad
```

#### Por navegador
```bash
npx playwright test --project=chromium  # Solo Chrome
npx playwright test --project=firefox   # Solo Firefox
npx playwright test --project=webkit    # Solo Safari
```

#### Modo debug
```bash
npx playwright test --debug
```

### 5. Ver reportes
```bash
npx playwright show-report
```

## 🧪 Tipos de Pruebas

### � Smoke Tests (`smoke.spec.js`)
- Verificación básica de carga de la aplicación
- Login básico funcional
- Accesibilidad de páginas críticas
- Navegación fundamental
- Respuesta de formularios
- Ausencia de errores críticos de JavaScript

### �🔐 Autenticación (`login.spec.js`)
- Login exitoso con credenciales válidas
- Manejo de credenciales incorrectas
- Validación de campos requeridos
- Redirección post-autenticación
- Persistencia de sesión entre páginas

### 📝 Registro (`register.spec.js`)
- Verificación de formulario completo
- Validación de contraseñas coincidentes
- Manejo de campos vacíos
- Registro exitoso con datos válidos

### 🧭 Navegación (`navigation.spec.js`)
- Funcionamiento de menús principales
- Navegación con botones del navegador
- Verificación de elementos del footer
- Funcionalidad de búsqueda

### ✅ Validación de Formularios (`form-validation.spec.js`)
- Validación de formato de email
- Restricciones de longitud de contraseña
- Verificación de campos requeridos
- Manejo de caracteres especiales

### 🛡️ Seguridad (`security-tests.spec.js`)
- Protección contra inyección SQL
- Prevención de Cross-Site Scripting (XSS)
- Manejo de entradas extremas
- Validación de caracteres Unicode
- Pruebas de múltiples intentos fallidos

### 🚗 Funcionalidades Específicas (`buggy-features.spec.js`)
- Acceso a perfil de usuario
- Exploración del catálogo de autos
- Sistema de votación y rating
- Responsividad en dispositivos móviles
- Búsqueda específica de vehículos

## 📊 Resultados

### Métricas Generales
- **Total de pruebas:** 93
- **Pruebas exitosas:** 75 (80.6%)
- **Tiempo de ejecución:** ~5.1 minutos
- **Navegadores probados:** 3

### Resultados por Navegador
| Navegador | Exitosas | Total | Tasa de Éxito |
|-----------|----------|--------|---------------|
| Chrome    | 25/31    | 31     | 80.6%         |
| Firefox   | 25/31    | 31     | 80.6%         |
| Safari    | 25/31    | 31     | 80.6%         |

### Estado de Funcionalidades
| Funcionalidad | Estado | Detalles |
|---------------|--------|----------|
| Autenticación | ✅ Operativa | Login/logout funcionando |
| Registro | ✅ Operativa | Validaciones implementadas |
| Navegación | ✅ Operativa | Enlaces funcionales |
| Formularios | ✅ Operativa | Validaciones HTML5 activas |
| Seguridad | ✅ Protegida | SQL injection y XSS bloqueados |
| Features Específicas | ✅ Operativa | Catálogo y rating funcionales |

## 🛡️ Validaciones de Seguridad

### ✅ Protección contra Inyección SQL
La aplicación bloquea correctamente los siguientes payloads:
```sql
' OR '1'='1
admin'--
' OR 1=1--
admin' OR 1=1#
```

### ✅ Protección contra XSS
Los siguientes intentos de XSS son filtrados apropiadamente:
```html
<script>alert("XSS")</script>
<img src="x" onerror="alert(1)">
javascript:alert("XSS")
<svg onload="alert(1)">
```

### ✅ Manejo de Datos Extremos
- Strings de 1000+ caracteres manejados correctamente
- Soporte completo para caracteres Unicode y emojis
- Validación apropiada de límites de entrada

## 📖 Documentación

- **[📋 Informe Técnico Completo](INFORME_TECNICO.md)** - Análisis detallado y resultados
- **[📊 Resumen Ejecutivo](RESUMEN_EJECUTIVO.md)** - Resumen para presentaciones
- **[📚 Documentación de Playwright](https://playwright.dev/)** - Framework utilizado

### Credenciales de Prueba
- **Usuario:** Marco@gmail.com
- **Contraseña:** Marco123/
- **Nombre:** Marco
- **Apellido:** Tulio

### Aplicación Bajo Prueba
- **URL:** https://buggy.justtestit.org/
- **Tipo:** Aplicación web de rating de autos
- **Propósito:** Plataforma de pruebas para QA

## 🔧 Configuración Avanzada

### Configuración de Playwright
```javascript
// playwright.config.js
export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } }
  ]
});
```

### Variables de Entorno
```bash
# Para ejecución en CI/CD
CI=true npx playwright test

# Para debug verbose
DEBUG=pw:api npx playwright test
```

## 🤝 Contribución

Este proyecto es parte del curso de **Aseguramiento de la Calidad del Software**. Las contribuciones son bienvenidas siguiendo estas pautas:

1. Fork del repositorio
2. Crear branch para feature (`git checkout -b feature/nueva-prueba`)
3. Commit de cambios (`git commit -m 'Agregar nueva prueba de...'`)
4. Push al branch (`git push origin feature/nueva-prueba`)
5. Crear Pull Request

## 📄 Licencia

Este proyecto es de uso educativo para el curso de Aseguramiento de la Calidad del Software.

## 👨‍💻 Autor

**Marco Tulio**
- 📧 Email: [tu-email@ejemplo.com]
- 🐙 GitHub: [@tulio67](https://github.com/tulio67)
- 📚 Curso: Aseguramiento de la Calidad del Software
- 📅 Fecha: Octubre 2025

---

### 🚀 ¿Listo para ejecutar las pruebas?

```bash
git clone https://github.com/tulio67/ProyectoFinal.git
cd ProyectoFinal
npm install
npx playwright install
npx playwright test
```

### 🚬 Smoke Tests - Comandos Adicionales
```bash
# Smoke tests rápidos (solo Chrome)
npm run smoke:fast

# Smoke tests completos (todos los navegadores)
npm run smoke

# Smoke tests con debug
npx playwright test smoke.spec.js --debug
```

**¡Aseguramiento de calidad en acción!** 🎯✨