---
id: "imagepanick-svg-rce-imagemagick-ghostscript"
title: "ImagePanick: De SVG a RCE encadenando políticas débiles y bugs en ImageMagick y Ghostscript"
author: "eric-labrador"
publishedDate: 2026-03-19
updatedDate: 2026-03-19
image: ""
description: "Cómo un solo archivo SVG consigue escritura arbitraria de archivos (y RCE) encadenando políticas por defecto débiles en ImageMagick con vulnerabilidades en Ghostscript 10.06.0, saltándose completamente el modo SAFER de GS."
categories:
  - "vulnerability-research"
draft: false
featured: false
lang: "es"
---

Si alguna vez has subido una imagen a una web y se ha redimensionado, se le ha generado un _thumbnail_ o se ha convertido a otro formato, lo más probable es que **ImageMagick** estuviera detrás. Es la suite _open-source_ de referencia para procesamiento de imágenes ya que la usan innumerables aplicaciones web, CMS, _pipelines_ de documentos y servicios _backend_ para manipular imágenes al vuelo. Maneja de todo: desde PNGs y JPEGs hasta formatos más exóticos como SVG, EPS y PostScript.

Para estos últimos — EPS y PostScript — ImageMagick no hace el trabajo pesado por sí mismo. Lo delega a **Ghostscript**, otro proyecto _open-source_ ampliamente desplegado que actúa como intérprete del lenguaje PostScript y archivos PDF. Ghostscript está en todas partes: impresoras, visores de PDF, conversores de documentos, y sí, como _backend_ de ImageMagick cada vez que necesita lidiar con contenido vectorial/PostScript.

Ambos proyectos son infraestructura _fundacional_. Corren en millones de servidores, muchas veces procesando _input_ de usuarios no confiables. Lo cual hace que lo que voy a mostrar sea especialmente preocupante.

¿Qué pasaría si te dijera que un simple archivo SVG — de los que tu navegador renderiza a diario — puede darle a un atacante acceso de escritura total a tu sistema de archivos? ¿Y que funciona contra la configuración por defecto de ImageMagick con Ghostscript?

Sí, yo tampoco me lo creía hasta que lo encontré.

Esta es la historia de cómo encadené **políticas por defecto débiles en ImageMagick** con **vulnerabilidades en Ghostscript 10.06.0** para pasar de un inocente `magick input.svg output.png` a **escritura arbitraria de archivos**, que escala trivialmente a **Ejecución Remota de Código (RCE)**.

- [TL;DR para los impacientes](#tldr-para-los-impacientes)
- [El punto de partida: una peculiaridad en el parser SVG](#el-punto-de-partida-una-peculiaridad-en-el-parser-svg)
- [Política débil 1: Inyección de Carriage Return en SVG → Inyección de comandos MVG](#política-débil-1-inyección-de-carriage-return-en-svg--inyección-de-comandos-mvg)
- [Política débil 2: El msl: que falta en la blacklist de ImageMagick](#política-débil-2-el-msl-que-falta-en-la-blacklist-de-imagemagick)
- [Vuln 1: El .tempfile de Ghostscript SAFER es demasiado generoso](#vuln-1-el-tempfile-de-ghostscript-safer-es-demasiado-generoso)
- [Vuln 2: Nombres de archivo predecibles con renamefile](#vuln-2-nombres-de-archivo-predecibles-con-renamefile)
- [Vuln 3: El SAFER moderno se olvida de cerrar con llave](#vuln-3-el-safer-moderno-se-olvida-de-cerrar-con-llave)
- [Juntando todo: la cadena completa](#juntando-todo-la-cadena-completa)
- [Prueba de Concepto y Laboratorio Docker](#prueba-de-concepto-y-laboratorio-docker)
- [Impacto: ¿A quién le debería importar?](#impacto-a-quién-le-debería-importar)
- [Mitigaciones](#mitigaciones)
- [Reflexiones finales](#reflexiones-finales)

## TL;DR para los impacientes

Un archivo SVG autocontenido encadena políticas por defecto débiles en ImageMagick (sanitización SVG insuficiente + _blacklist_ de protocolos incompleta) con vulnerabilidades de bypass de Ghostscript SAFER (`.tempfile` + `renamefile`) para conseguir **escritura arbitraria de archivos en disco**. Un solo comando desencadena todo: `magick input.svg output.png`. Sin interacción del usuario, sin _flags_ especiales, sin configuración rara. Solo los valores por defecto.

## El punto de partida: una peculiaridad en el parser SVG

Estaba trasteando con el código de _parsing_ SVG de ImageMagick cuando algo me llamó la atención en `coders/svg.c`. La función `SVGEscapeString` se supone que sanitiza los valores de cadena antes de incrustarlos en el formato intermedio MVG (Magick Vector Graphics):

```c
static inline char *SVGEscapeString(const char* value)
{
  escaped_value = EscapeString(value, '\"');
  for (p = escaped_value; *p != '\0'; p++)
    if (*p == '\n')       // Solo filtra \n (LF)
      *p = ' ';
  return(escaped_value);  // \r (CR) pasa sin filtrar
}
```

¿Ves el problema? Filtra `\n` (_line feed_, `0x0A`) pero **ignora completamente `\r`** (_carriage return_, `0x0D`). ¿Por qué importa? Porque el parser MVG también trata `\r` como separador de línea. Así que si puedes colar un `\r` en el valor de un atributo SVG... puedes inyectar comandos MVG arbitrarios.

Y colarlo es trivial. SVG es XML. XML tiene referencias de caracteres. `&#13;` es `\r`. Listo.

## Política débil 1: Inyección de Carriage Return en SVG → Inyección de comandos MVG

El atributo `points` de un elemento `<polyline>` se almacena mediante `CloneString` y luego se escribe directamente en el archivo MVG:

```c
// línea 2773 en coders/svg.c
(void) FormatLocaleFile(svg_info->file, "polyline %s\n", svg_info->vertices);
```

Sin escapado adicional. Así que este SVG:

```xml
<polyline points="0,0 50,50&#13;COMANDO INYECTADO AQUÍ&#13;100,0"/>
```

Produce este MVG:

```
polyline 0,0 50,50
COMANDO INYECTADO AQUÍ
100,0
```

Ya tenemos inyección MVG. La pregunta es: ¿qué comandos MVG son lo suficientemente peligrosos para llevarnos a algún sitio?

La respuesta es `image Over X,Y W,H 'URL'`, que carga y compone una imagen desde una URL — y esa URL puede usar los _protocol handlers_ internos de ImageMagick. Cosas como `data:`, `msl:`, `ephemeral:`...

## Política débil 2: El msl: que falta en la blacklist de ImageMagick

ImageMagick no es completamente ingenuo con esto. En `MagickCore/draw.c`, hay una _blacklist_ para la primitiva `image`:

```c
// draw.c, líneas 5667-5671
if ((LocaleCompare(clone_info->magick, "ftp") != 0) &&
    (LocaleCompare(clone_info->magick, "http") != 0) &&
    (LocaleCompare(clone_info->magick, "https") != 0) &&
    (LocaleCompare(clone_info->magick, "mvg") != 0) &&
    (LocaleCompare(clone_info->magick, "vid") != 0))
  composite_images = ReadImage(clone_info, exception);
```

Bloquea `ftp`, `http`, `https`, `mvg` y `vid`. Razonable. Pero **no bloquea `msl:`**.

MSL significa _Magick Scripting Language_. Es básicamente XML que le dice a ImageMagick que lea y escriba imágenes. Incluyendo en **rutas arbitrarias**:

```xml
<image>
  <read filename="xc:red[10x10]"/>
  <write filename="png:/cualquier/ruta/que/quieras.png"/>
</image>
```

Así que si podemos meter un archivo MSL en disco en una ruta conocida, podemos referenciarlo vía `msl:/ruta/al/archivo` desde nuestro MVG inyectado, e ImageMagick lo ejecutará encantado. Eso nos da escritura arbitraria de archivos.

Pero necesitamos el archivo en disco primero. Entra Ghostscript.

## Vuln 1: El .tempfile de Ghostscript SAFER es demasiado generoso

ImageMagick delega el procesamiento de EPS/PostScript a Ghostscript. Y gracias a las URIs `data:image/x-eps;base64,...`, podemos incrustar un _payload_ EPS directamente en nuestro SVG — sin necesidad de archivos externos.

Ghostscript corre en modo SAFER por defecto, que se supone que restringe el acceso al sistema de archivos. Pero el operador PostScript `.tempfile` está _diseñado_ para funcionar bajo SAFER. Crea un archivo temporal vía `mkstemp` y luego — aquí viene lo jugoso — añade la ruta resultante a las **listas de permisos a nivel de C** para lectura, escritura Y control:

```c
// base/gpmisc.c, líneas 800-807
code = gs_add_control_path_flags(mem, gs_permit_file_control, fname, ...);
code = gs_add_control_path_flags(mem, gs_permit_file_reading, fname, ...);
code = gs_add_control_path_flags(mem, gs_permit_file_writing, fname, ...);
```

Esto significa que desde PostScript podemos:
1. Llamar a `.tempfile` → obtenemos un _file handle_ escribible en una ruta aleatoria como `/tmp/gs_aB3x7Q`
2. Escribir lo que queramos con `writestring`

Ya tenemos contenido arbitrario en disco... pero en una ruta aleatoria que no podemos predecir desde el SVG.

## Vuln 2: Nombres de archivo predecibles con renamefile

El operador PostScript `renamefile` valida tanto la ruta origen como la destino usando `gp_validate_path`. Como `.tempfile` ya añadió el directorio temporal a las listas de permisos, renombrar un archivo _dentro del mismo directorio temporal_ funciona:

```postscript
% PostScript dentro de nuestro payload EPS
null (w) .tempfile /f exch def /n exch def
f (contenido del payload MSL aquí) writestring
f closefile
n (/tmp/payload.msl) renamefile
```

Archivo temporal con nombre aleatorio → **archivo temporal con nombre predecible**. Ahora sabemos exactamente dónde está nuestro _payload_ MSL.

## Vuln 3: El SAFER moderno se olvida de cerrar con llave

Una cosa más que hace que esta cadena funcione sin problemas. En Ghostscript 10.06.0, el modo SAFER "moderno" (`OLDSAFER=false`, que es el valor por defecto) tiene un descuido en `Resource/Init/gs_init.ps`:

El procedimiento `.setsafeglobal`:
- Llama a `.lockfileaccess` (activa el control de rutas a nivel de C) ✓
- Llama a `SAFERUndefinePostScriptOperators` (elimina operadores peligrosos) ✓
- **NO** llama a `.locksafe` (que pondría `LockSafetyParams=true`) ✗

Esto significa que los parámetros del _device_ como `OutputFile` todavía se pueden cambiar desde PostScript. Aunque la cadena actual no lo necesita estrictamente, amplía considerablemente la superficie de ataque para caminos de explotación alternativos.

## Juntando todo: la cadena completa

Aquí está el ataque completo visualizado:

```
SVG con &#13; en <polyline points="...">
  │
  ├─ Fase 1: MVG inyectado "image" carga data:image/x-eps;base64,...
  │   └─ Ghostscript SAFER ejecuta el payload EPS:
  │       ├─ .tempfile  → crea archivo escribible
  │       ├─ writestring → escribe el payload MSL XML en él
  │       └─ renamefile  → renombra a /tmp/payload.msl (ruta conocida)
  │
  └─ Fase 2: MVG inyectado "image" carga msl:/tmp/payload.msl
      └─ ImageMagick ejecuta MSL:
          └─ <write filename="png:/ruta/arbitraria/archivo.png"/>
              └─ ESCRITURA ARBITRARIA DE ARCHIVOS → RCE
```

Dos políticas débiles por defecto. Tres vulnerabilidades en Ghostscript. Un archivo SVG. Cero interacción del usuario más allá de ejecutar `magick`.

## Prueba de Concepto y Laboratorio Docker

El _exploit_ completo cabe en un solo archivo SVG autocontenido. He publicado la PoC completa junto con un laboratorio Docker listo para usar, para que puedas reproducir el problema de forma segura en un entorno aislado:

**[https://github.com/e1abrador/ImagePanick/](https://github.com/e1abrador/ImagePanick/?utm_source=deephacking.tech)**

El repositorio incluye el script generador del SVG, instrucciones paso a paso, y un entorno Dockerizado con las versiones vulnerables de ImageMagick y Ghostscript preinstaladas. Solo `docker build`, `docker run`, y verás la escritura arbitraria de archivos en tiempo real.

## Impacto: ¿A quién le debería importar?

Básicamente a cualquiera que procese SVGs no confiables con ImageMagick. Y eso es... _mucho_ software:

- **Aplicaciones web** que redimensionan o generan _thumbnails_ de SVGs subidos (fotos de perfil, adjuntos de CMS, posts en foros)
- **Pipelines de procesamiento de documentos** (generadores de PDF que aceptan SVG como _input_)
- **Sistemas CI/CD** que procesan imágenes como parte del _build_
- **Cualquier flujo automatizado de procesamiento de SVG** — incluso algo tan simple como generar _thumbnails_ de subidas de usuarios

La escalación de escritura arbitraria de archivos a **RCE completo** es trivial:

- Escribir en `~/.bashrc` o `~/.profile` → ejecución de código en el siguiente _login_
- Escribir en `/etc/cron.d/` o `/var/spool/cron/` → ejecución programada
- Escribir en un directorio accesible por web → _webshell_
- Escribir en `~/.ssh/authorized_keys` → acceso SSH

El ataque no requiere **autenticación, ni _flags_ especiales, ni configuración no estándar**. El _delegate_ de Ghostscript viene habilitado por defecto en la mayoría de instalaciones de ImageMagick.

## Mitigaciones

Hasta que salgan los parches:

1. **Deshabilitar el _delegate_ de Ghostscript** en `delegates.xml` si no necesitas soporte EPS/PS (la mayoría de aplicaciones web no lo necesitan).
2. **Usar el policy.xml de ImageMagick** para bloquear los _coders_ SVG, EPS, PS y MSL explícitamente:
   ```xml
   <policy domain="coder" rights="none" pattern="{SVG,EPS,PS,MSL}" />
   ```
3. **Sandboxear ImageMagick** con algo como `nsjail`, `firejail`, o aislamiento por contenedor con un sistema de archivos de solo lectura y un tmpdir restringido.
4. **No procesar SVGs no confiables con ImageMagick** si puedes evitarlo. Usa un rasterizador SVG dedicado como `librsvg` — no invoca Ghostscript.

## Reflexiones finales

Lo que me parece más interesante de esta cadena es cómo distintos tipos de problemas se combinan para crear algo mucho mayor que la suma de sus partes. En el lado de ImageMagick, no estamos ante vulnerabilidades tradicionales — son **políticas por defecto débiles**. La sanitización de CR es incompleta, y la _blacklist_ de protocolos no cubre `msl:`. Ninguna de estas cosas es un _bug_ en el sentido clásico; son decisiones de diseño que dejan la puerta abierta cuando se combinan con otros problemas. ImageMagick proporciona las herramientas para cerrar todo (vía `policy.xml`), pero los valores por defecto son demasiado permisivos.

En el lado de Ghostscript, la historia es diferente. La escalación de permisos de `.tempfile`, el _path traversal_ de `renamefile` dentro de directorios temporales, y la llamada a `.locksafe` que falta en el SAFER moderno son vulnerabilidades genuinas — comportamientos que rompen las garantías de seguridad que el modo SAFER se supone que proporciona.

¿Pero encadenados — políticas débiles encontrándose con bugs reales a través de las fronteras entre proyectos? RCE completo desde un solo archivo SVG.

Este es el tipo de cosas que hacen que la investigación de seguridad sea fascinante. Los problemas de ImageMagick por sí solos son discutiblemente "funcionando como diseñado" con valores por defecto débiles. Los bugs de Ghostscript por sí solos necesitan una vía para alcanzarlos. Pero cuando combinas valores por defecto permisivos en un proyecto con escapes de _sandbox_ en otro, el resultado socava completamente el modelo de seguridad.

La solución en el lado de ImageMagick pasa por endurecer las políticas por defecto — añadir `\r` al filtro de sanitización, añadir `msl:` a la _blacklist_ de protocolos, y distribuir valores por defecto más restrictivos. En el lado de Ghostscript, las correcciones son más tradicionales — restringir los destinos de `renamefile`, limitar el alcance de los permisos de `.tempfile`, y llamar a `.locksafe` en el SAFER moderno. Pero encontrar la cadena requirió entender cómo todas estas piezas interactúan a través de las fronteras entre proyectos.

Si tienes ImageMagick en producción con soporte SVG: revisa tu `policy.xml`. Hoy.

Happy Hacking!

