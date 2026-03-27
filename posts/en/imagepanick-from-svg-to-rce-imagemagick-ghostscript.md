---
id: "imagepanick-svg-rce-imagemagick-ghostscript"
title: "ImagePanick: From SVG to RCE Chaining Weak Policies and Bugs in ImageMagick and Ghostscript"
author: "eric-labrador"
publishedDate: 2026-03-19
updatedDate: 2026-03-19
image: ""
description: "How a single SVG file can achieve arbitrary file write (and RCE) by chaining weak default policies in ImageMagick with vulnerabilities in Ghostscript 10.06.0, completely bypassing GS SAFER mode."
categories:
  - "vulnerability-research"
draft: false
featured: false
lang: "en"
---

If you've ever uploaded an image to a website and it got resized, thumbnailed, or converted to another format, there's a good chance **ImageMagick** was behind it. It's the go-to open-source suite for image processing — used by countless web apps, CMS platforms, document pipelines, and backend services to manipulate images on the fly. It handles everything from PNGs and JPEGs to more exotic formats like SVG, EPS, and PostScript.

For those last ones — EPS and PostScript — ImageMagick doesn't do the heavy lifting itself. It delegates to **Ghostscript**, another widely-deployed open-source project that acts as an interpreter for the PostScript language and PDF files. Ghostscript is everywhere: printers, PDF viewers, document converters, and yes, as a backend for ImageMagick whenever it needs to deal with vector/PostScript content.

Both projects are _foundational_ infrastructure. They run on millions of servers, often processing untrusted user input. Which makes what I'm about to show you particularly concerning.

What if I told you a single SVG file — the kind your browser renders every day — could give an attacker full write access to your filesystem? And that it works against the default configuration of ImageMagick with Ghostscript?

Yeah, I didn't believe it either until I found it.

This is the story of how I chained **weak default policies in ImageMagick** with **vulnerabilities in Ghostscript 10.06.0** to go from a harmless-looking `magick input.svg output.png` to **arbitrary file write**, which trivially escalates to **Remote Code Execution**.

- [TL;DR for the Impatient](#tldr-for-the-impatient)
- [The Starting Point: A Weird SVG Parser Quirk](#the-starting-point-a-weird-svg-parser-quirk)
- [Weak Policy 1: Carriage Return Injection in SVG → MVG Command Injection](#weak-policy-1-carriage-return-injection-in-svg--mvg-command-injection)
- [Weak Policy 2: The Missing msl: in ImageMagick's Blacklist](#weak-policy-2-the-missing-msl-in-imagemagicks-blacklist)
- [Vuln 1: Ghostscript SAFER .tempfile Is Too Generous](#vuln-1-ghostscript-safer-tempfile-is-too-generous)
- [Vuln 2: Predictable Filenames via renamefile](#vuln-2-predictable-filenames-via-renamefile)
- [Vuln 3: Modern SAFER Forgets to Lock the Door](#vuln-3-modern-safer-forgets-to-lock-the-door)
- [Putting It All Together: The Full Chain](#putting-it-all-together-the-full-chain)
- [Proof of Concept & Docker Lab](#proof-of-concept--docker-lab)
- [Impact: Who Should Care?](#impact-who-should-care)
- [Mitigations](#mitigations)
- [Final Thoughts](#final-thoughts)

## TL;DR for the Impatient

A self-contained SVG file chains weak default policies in ImageMagick (insufficient SVG sanitization + incomplete protocol blacklist) with Ghostscript SAFER bypass vulnerabilities (`.tempfile` + `renamefile`) to achieve **arbitrary file write on disk**. One command triggers everything: `magick input.svg output.png`. No user interaction, no special flags, no weird config. Just the defaults.

## The Starting Point: A Weird SVG Parser Quirk

I was poking around ImageMagick's SVG parsing code when something caught my eye in `coders/svg.c`. The function `SVGEscapeString` is supposed to sanitize string values before they get embedded in the intermediate MVG (Magick Vector Graphics) format:

```c
static inline char *SVGEscapeString(const char* value)
{
  escaped_value = EscapeString(value, '\"');
  for (p = escaped_value; *p != '\0'; p++)
    if (*p == '\n')       // Only filters \n (LF)
      *p = ' ';
  return(escaped_value);  // \r (CR) passes through unfiltered
}
```

See the problem? It filters `\n` (line feed, `0x0A`) but **completely ignores `\r`** (carriage return, `0x0D`). Why does this matter? Because the MVG parser treats `\r` as a line separator too. So if you can sneak a `\r` into an SVG attribute value... you can inject arbitrary MVG commands.

And sneaking it in is trivial. SVG is XML. XML has character references. `&#13;` is `\r`. Done.

## Weak Policy 1: Carriage Return Injection in SVG → MVG Command Injection

The `points` attribute of a `<polyline>` element gets stored via `CloneString` and then written directly into the MVG file:

```c
// line 2773 in coders/svg.c
(void) FormatLocaleFile(svg_info->file, "polyline %s\n", svg_info->vertices);
```

No additional escaping. So this SVG:

```xml
<polyline points="0,0 50,50&#13;INJECTED COMMAND HERE&#13;100,0"/>
```

Produces this MVG:

```
polyline 0,0 50,50
INJECTED COMMAND HERE
100,0
```

Now we have MVG injection. The question becomes: what MVG commands are dangerous enough to get us somewhere?

The answer is `image Over X,Y W,H 'URL'`, which loads and composites an image from a URL — and that URL can use ImageMagick's internal protocol handlers. Things like `data:`, `msl:`, `ephemeral:`...

## Weak Policy 2: The Missing msl: in ImageMagick's Blacklist

ImageMagick isn't completely naive about this. In `MagickCore/draw.c`, there's a blacklist for the `image` primitive:

```c
// draw.c, lines 5667-5671
if ((LocaleCompare(clone_info->magick, "ftp") != 0) &&
    (LocaleCompare(clone_info->magick, "http") != 0) &&
    (LocaleCompare(clone_info->magick, "https") != 0) &&
    (LocaleCompare(clone_info->magick, "mvg") != 0) &&
    (LocaleCompare(clone_info->magick, "vid") != 0))
  composite_images = ReadImage(clone_info, exception);
```

It blocks `ftp`, `http`, `https`, `mvg`, and `vid`. Reasonable enough. But it **doesn't block `msl:`**.

MSL stands for _Magick Scripting Language_. It's basically XML that tells ImageMagick to read and write images. Including to **arbitrary paths**:

```xml
<image>
  <read filename="xc:red[10x10]"/>
  <write filename="png:/any/path/you/want.png"/>
</image>
```

So if we can get an MSL file on disk at a known path, we can reference it via `msl:/path/to/file` from our injected MVG, and ImageMagick will happily execute it. That gives us arbitrary file write.

But we need the file on disk first. Enter Ghostscript.

## Vuln 1: Ghostscript SAFER .tempfile Is Too Generous

ImageMagick delegates EPS/PostScript processing to Ghostscript. And thanks to `data:image/x-eps;base64,...` URIs, we can embed an EPS payload directly in our SVG — no external files needed.

Ghostscript runs in SAFER mode by default, which is supposed to restrict file system access. But the `.tempfile` PostScript operator is _designed_ to work under SAFER. It creates a temp file via `mkstemp` and then — here's the juicy part — adds the resulting path to the **C-level permit lists** for reading, writing, AND control:

```c
// base/gpmisc.c, lines 800-807
code = gs_add_control_path_flags(mem, gs_permit_file_control, fname, ...);
code = gs_add_control_path_flags(mem, gs_permit_file_reading, fname, ...);
code = gs_add_control_path_flags(mem, gs_permit_file_writing, fname, ...);
```

This means from PostScript we can:
1. Call `.tempfile` → get a writable file handle at some random path like `/tmp/gs_aB3x7Q`
2. Write whatever we want to it with `writestring`

We now have arbitrary file content on disk... but at a random path we can't predict from the SVG.

## Vuln 2: Predictable Filenames via renamefile

The `renamefile` PostScript operator validates both source and destination paths using `gp_validate_path`. Since `.tempfile` already added the temp directory to the permit lists, renaming a file _within the same temp directory_ succeeds:

```postscript
% PostScript inside our EPS payload
null (w) .tempfile /f exch def /n exch def
f (MSL payload content here) writestring
f closefile
n (/tmp/payload.msl) renamefile
```

Random-name temp file → **predictable-name temp file**. Now we know exactly where our MSL payload lives.

## Vuln 3: Modern SAFER Forgets to Lock the Door

One more thing that makes this chain work smoothly. In Ghostscript 10.06.0, the "modern" SAFER mode (`OLDSAFER=false`, which is the default) has an oversight in `Resource/Init/gs_init.ps`:

The `.setsafeglobal` procedure:
- Calls `.lockfileaccess` (activates C-level path control) ✓
- Calls `SAFERUndefinePostScriptOperators` (removes dangerous ops) ✓
- Does **NOT** call `.locksafe` (which would set `LockSafetyParams=true`) ✗

This means device parameters like `OutputFile` can still be changed from PostScript. While the current chain doesn't strictly need this, it widens the attack surface considerably for alternative exploitation paths.

## Putting It All Together: The Full Chain

Here's the full attack visualized:

```
SVG with &#13; in <polyline points="...">
  │
  ├─ Stage 1: Injected MVG "image" loads data:image/x-eps;base64,...
  │   └─ Ghostscript SAFER executes EPS payload:
  │       ├─ .tempfile  → creates writable file
  │       ├─ writestring → writes MSL XML payload to it
  │       └─ renamefile  → renames to /tmp/payload.msl (known path)
  │
  └─ Stage 2: Injected MVG "image" loads msl:/tmp/payload.msl
      └─ ImageMagick executes MSL:
          └─ <write filename="png:/arbitrary/path/file.png"/>
              └─ ARBITRARY FILE WRITE → RCE
```

Two weak default policies. Three Ghostscript vulnerabilities. One SVG file. Zero user interaction beyond running `magick`.

## Proof of Concept & Docker Lab

The entire exploit fits in a single self-contained SVG file. I've published the full PoC along with a ready-to-use Docker lab so you can safely reproduce the issue in an isolated environment:

**[https://github.com/e1abrador/ImagePanick/](https://github.com/e1abrador/ImagePanick/?utm_source=deephacking.tech)**

The repo includes the SVG generator script, step-by-step instructions, and a Dockerized environment with the vulnerable versions of ImageMagick and Ghostscript pre-installed. Just `docker build`, `docker run`, and see the arbitrary file write happen in real time.

## Impact: Who Should Care?

Basically anyone processing untrusted SVGs with ImageMagick. And that's... _a lot_ of software:

- **Web apps** that resize or thumbnail SVG uploads (think profile pictures, CMS attachments, forum posts)
- **Document processing pipelines** (PDF generators that accept SVG input)
- **CI/CD systems** that process images as part of build steps
- **Any automated SVG processing workflow** — even something as simple as generating thumbnails from user uploads

Escalation from arbitrary file write to **full RCE** is trivial:

- Write to `~/.bashrc` or `~/.profile` → code execution on next login
- Write to `/etc/cron.d/` or `/var/spool/cron/` → scheduled execution
- Write to a web-accessible directory → webshell
- Write to `~/.ssh/authorized_keys` → SSH access

The attack requires **no authentication, no special flags, no non-default configuration**. The Ghostscript delegate is enabled by default in most ImageMagick installations.

## Mitigations

Until patches land:

1. **Disable the Ghostscript delegate** in `delegates.xml` if you don't need EPS/PS support (most web apps don't).
2. **Use ImageMagick's policy.xml** to block SVG, EPS, PS, and MSL coders explicitly:
   ```xml
   <policy domain="coder" rights="none" pattern="{SVG,EPS,PS,MSL}" />
   ```
3. **Sandbox ImageMagick** with something like `nsjail`, `firejail`, or container isolation with a read-only filesystem and a restricted tmpdir.
4. **Don't process untrusted SVGs with ImageMagick** if you can avoid it. Use a dedicated SVG rasterizer like `librsvg` instead — it doesn't shell out to Ghostscript.

## Final Thoughts

What I find most interesting about this chain is how different types of issues combine to create something much bigger than the sum of their parts. On the ImageMagick side, we're not looking at traditional vulnerabilities — these are **weak default policies**. The CR sanitization is incomplete, and the protocol blacklist doesn't cover `msl:`. Neither of these is a bug in the classical sense; they're design decisions that leave the door open when combined with other issues. ImageMagick provides the tools to lock things down (via `policy.xml`), but the defaults are too permissive.

On the Ghostscript side, the story is different. The `.tempfile` permit escalation, the `renamefile` path traversal within temp directories, and the missing `.locksafe` call in modern SAFER are genuine vulnerabilities — behaviors that break the security guarantees SAFER mode is supposed to provide.

But chained together — weak policies meeting real bugs across project boundaries? Full RCE from a single SVG file.

This is the kind of thing that makes security research fascinating. The ImageMagick issues on their own are arguably "working as designed" with weak defaults. The Ghostscript bugs on their own require a way to reach them. But when you combine permissive defaults in one project with sandbox escapes in another, the result completely undermines the security model.

The fix on the ImageMagick side is about tightening default policies — add `\r` to the sanitization filter, add `msl:` to the protocol blacklist, and ship more restrictive defaults. On Ghostscript's end, the fixes are more traditional — restrict `renamefile` destinations, limit `.tempfile` permit scope, and call `.locksafe` in modern SAFER. But finding the chain required understanding how all these pieces interact across project boundaries.

If you're running ImageMagick in production with SVG support: check your `policy.xml`. Today.

Happy Hacking!
