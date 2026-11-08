---
trigger: always_on
description: Reglas de orquestación multi-agente (Planificador y Constructor), enrutamiento dinámico de modelos según complejidad y actualización del panel de observabilidad.
---

# Reglas de Orquestación Multi-Agente, Enrutamiento de Modelos y Observabilidad

Este conjunto de directivas rige el comportamiento del asistente para maximizar la eficiencia en costos, la precisión en desarrollo y la transparencia operativa.

---

## 1. Enrutamiento Dinámico de Modelos por Complejidad (Model Routing)

Antes de delegar o ejecutar una tarea, el sistema debe evaluar el nivel de complejidad y seleccionar el modelo óptimo al invocar subagentes (`invoke_subagent`):

| Nivel de Complejidad | Criterios / Tipo de Tarea | Modelo Asignado |
| :--- | :--- | :--- |
| **Baja (Trivial / Mecánica)** | Búsquedas simples de archivos, formateo de texto/JSON, scripts estándar < 50 líneas, documentación básica, tareas repetitivas. | `flash_lite` |
| **Media (Estándar / Ejecución)** | Implementación de módulos bien definidos, redacción de tests unitarios, refactorizaciones locales, integración de APIs comunes. | `flash` |
| **Alta (Crítica / Razonamiento)** | Diseño de arquitectura de software, debugging de errores complejos/multicapa, optimización algorítmica, análisis de seguridad. | `pro` |

> **Regla de Oro:** Siempre utilizar el modelo más económico que garantice el 100% de éxito en la tarea. No delegar tareas mecánicas al modelo `pro`.

---

## 2. Patrón de Trabajo Dual: Planificador & Constructor

Toda tarea no trivial (>1 archivo afectado o lógica de negocio nueva) debe ejecutarse bajo el flujo de dos subagentes especializados:

```
[Usuario / Requerimiento]
          │
          ▼
┌─────────────────────────┐
│ 1. Mini-Agente          │   (Modelo: 'pro' o 'flash')
│    PLANIFICADOR         │   Genera: Arquitectura, Tareas y Criterios
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ Puerta Human-in-the-loop│   Validación / Aprobación del usuario
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ 2. Mini-Agente          │   (Modelo: 'flash' o 'flash_lite')
│    CONSTRUCTOR          │   Escribe código, corre pruebas, construye
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ Actualización de Panel  │   Refleja estado final y artefactos
└─────────────────────────┘
```

### 2.1. Mini-Agente Planificador (Planner / Architect)
- **Rol:** Analizar el contexto, anticipar dependencias, definir la estructura de archivos y establecer los criterios de aceptación.
- **Entregable:** Artefacto de Plan estructurado con pasos atómicos y bien delimitados.
- **Restricción:** El Planificador no edita código de producción, únicamente genera el mapa de ruta.

### 2.2. Mini-Agente Constructor (Builder / Developer)
- **Rol:** Tomar el plan validado y ejecutarlo secuencialmente. Escribe código modular, ejecuta comandos de prueba y asegura que no se rompan funcionalidades existentes.
- **Entregable:** Archivos de código, suites de pruebas y logs de verificación.

---

## 3. Observabilidad y Panel de Control (Agent Dashboard)

Cada vez que se active un flujo con mini-agentes:
1. **Actualización Obligatoria:** Se debe mantener actualizado el archivo del panel interactivo local (`agent_dashboard.html`).
2. **Campos del Panel:**
   - **Agentes Activos:** Estado actual (Inactivo, Planificando, Construyendo, Finalizado).
   - **Modelo en Uso:** Indicador de si se está usando `flash_lite`, `flash` o `pro`.
   - **Lista de Tareas:** Desglose con estados (Pendiente, En Proceso, Completado).
   - **Bitácora de Eventos:** Registro cronológico de acciones ejecutadas y archivos generados.
3. **Acceso al Usuario:** Tras cada hito, proveer el enlace directo para visualizar o abrir el panel en el navegador.
