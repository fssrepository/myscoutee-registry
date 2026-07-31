#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

const DOCUMENT_VERSION = '1.0.0';
const RELEASE_DATE = '2026-07-30';
const MINIMUM_PDF_BYTES = 10_000;
const validateOnly = process.env.DOCS_VALIDATE_ONLY === 'true';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '..', '..');

const manuals = [
  {
    source: 'myscoutee-registry-operator-manual-en.html',
    output: 'MyScoutee_Registry_Operator_Manual_v1.0.0_EN.pdf',
    documentId: 'MSC-ROM-001',
    title: 'Registry Operator Manual',
    heading: 'MyScoutee Registry Operator Manual'
  },
  {
    source: 'myscoutee-registry-protocol-developer-manual-en.html',
    output: 'MyScoutee_Registry_Protocol_Developer_Manual_v1.0.0_EN.pdf',
    documentId: 'MSC-RPDM-001',
    title: 'Registry Protocol Developer Manual',
    heading: 'MyScoutee Registry Protocol Developer Manual'
  }
];

const sourcePaths = manuals.map(manual => path.join(scriptDirectory, manual.source));
const protocolEvidencePaths = [
  'protocol-v1.md',
  'operator-network-v1.md',
  'global-identity-v1.md',
  'announcements-v1.md',
  'registry-cases-v1.md',
  'settlements-v1.md',
  'exit-reviews-v1.md',
  'ownership-transfers-v1.md',
  'final-exit-allocations-v1.md',
  'production-qualification.md',
  'examples/announcement-general.json',
  'examples/announcement-update.json'
].map(relativePath => path.join(scriptDirectory, 'protocols', relativePath));
const staticAssetPaths = [
  path.join(scriptDirectory, 'myscoutee-logo.png')
];
const plannedOutputPaths = new Set(
  manuals.map(manual => path.resolve(scriptDirectory, manual.output))
);

await requireAllSources([
  ...sourcePaths,
  ...protocolEvidencePaths,
  ...staticAssetPaths
]);

const { chromium, resolution } = await loadPlaywright();
process.stdout.write(`Playwright: ${resolution}\n`);

const browserExecutable =
  process.env.DOCS_CHROME_PATH
  || (await firstExistingPath([
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser'
  ]));

if (process.env.DOCS_CHROME_PATH) {
  await assertFileExists(
    path.resolve(process.env.DOCS_CHROME_PATH),
    'DOCS_CHROME_PATH'
  );
}

const launchOptions = {
  headless: true,
  args: ['--disable-dev-shm-usage', '--font-render-hinting=none']
};
if (browserExecutable) {
  launchOptions.executablePath = browserExecutable;
}
if (process.getuid?.() === 0) {
  launchOptions.args.push('--no-sandbox');
}

const browser = await chromium.launch(launchOptions);
try {
  for (const manual of manuals) {
    await buildManual(browser, manual);
  }
} finally {
  await browser.close();
}

async function buildManual(browserInstance, manual) {
  const sourcePath = path.join(scriptDirectory, manual.source);
  const outputPath = path.join(scriptDirectory, manual.output);
  const temporaryOutputPath = `${outputPath}.tmp-${process.pid}`;
  const runtimeErrors = [];

  const page = await browserInstance.newPage({
    locale: 'en-GB',
    colorScheme: 'light',
    viewport: { width: 1280, height: 900 }
  });

  page.on('pageerror', error => {
    runtimeErrors.push(`page error: ${error.message}`);
  });
  page.on('console', message => {
    if (message.type() === 'error') {
      runtimeErrors.push(`console error: ${message.text()}`);
    }
  });
  page.on('requestfailed', request => {
    runtimeErrors.push(
      `request failed: ${request.url()} (${request.failure()?.errorText ?? 'unknown error'})`
    );
  });

  try {
    const response = await page.goto(pathToFileURL(sourcePath).href, {
      waitUntil: 'load'
    });
    if (response && !response.ok()) {
      runtimeErrors.push(
        `document load failed: HTTP ${response.status()} ${response.statusText()}`
      );
    }

    await page.emulateMedia({ media: 'print' });
    await page.evaluate(async () => {
      await document.fonts.ready;
      for (const image of document.images) {
        if (!image.complete) {
          await new Promise((resolve, reject) => {
            image.addEventListener('load', resolve, { once: true });
            image.addEventListener('error', reject, { once: true });
          });
        }
      }
    });

    const validation = await page.evaluate(expected => {
      const errors = [];
      const ids = [...document.querySelectorAll('[id]')]
        .map(element => element.id);
      const duplicateIds = [...new Set(
        ids.filter((id, index) => ids.indexOf(id) !== index)
      )];
      const missingTargets = [];

      for (const anchor of document.querySelectorAll('a[href^="#"]')) {
        const rawTarget = anchor.getAttribute('href')?.slice(1) ?? '';
        if (!rawTarget) {
          continue;
        }
        let target;
        try {
          target = decodeURIComponent(rawTarget);
        } catch {
          errors.push(`invalid percent encoding in internal link: #${rawTarget}`);
          continue;
        }
        if (!document.getElementById(target)) {
          missingTargets.push(target);
        }
      }

      const localTargets = [];
      for (const element of document.querySelectorAll(
        'a[href], img[src], script[src], link[href], source[src], video[poster]'
      )) {
        const attribute = element.hasAttribute('href')
          ? 'href'
          : element.hasAttribute('src')
            ? 'src'
            : 'poster';
        const rawValue = element.getAttribute(attribute)?.trim() ?? '';
        if (
          !rawValue
          || rawValue.startsWith('#')
          || rawValue.startsWith('//')
          || /^[a-z][a-z0-9+.-]*:/i.test(rawValue)
        ) {
          continue;
        }
        let resolved;
        try {
          resolved = new URL(rawValue, document.baseURI);
        } catch {
          errors.push(`invalid local ${attribute} target: ${rawValue}`);
          continue;
        }
        if (resolved.protocol === 'file:') {
          localTargets.push({
            attribute,
            tagName: element.tagName,
            rawValue,
            url: resolved.href
          });
        }
      }

      const rootLanguage = document.documentElement.lang.trim().toLowerCase();
      const pageTitle = document.title.trim();
      const coverHeading =
        document.querySelector('section.cover h1')?.textContent?.trim() ?? '';
      const coverMetadata =
        document.querySelector('section.cover .cover-meta, section.cover .metadata')
          ?.textContent
        ?? '';
      const figureCount = document.querySelectorAll('figure').length;

      if (rootLanguage !== 'en') {
        errors.push(`root lang must be "en", found "${rootLanguage || '(missing)'}"`);
      }
      if (!pageTitle.includes(expected.heading) || !pageTitle.includes(expected.documentId)) {
        errors.push(
          `HTML title must contain "${expected.heading}" and "${expected.documentId}"`
        );
      }
      if (!coverHeading) {
        errors.push('cover title heading is missing');
      }
      for (const selector of ['.manual', 'section.cover', '#document-control', '.toc']) {
        if (!document.querySelector(selector)) {
          errors.push(`required element is missing: ${selector}`);
        }
      }
      for (const requiredMetadata of [
        'Document ID',
        expected.documentId,
        'Document version',
        expected.version,
        'Release date',
        expected.releaseDate
      ]) {
        if (!coverMetadata.includes(requiredMetadata)) {
          errors.push(`cover metadata is missing: ${requiredMetadata}`);
        }
      }
      if (duplicateIds.length > 0) {
        errors.push(`duplicate HTML id: ${duplicateIds.join(', ')}`);
      }
      if (missingTargets.length > 0) {
        errors.push(
          `missing internal link target: ${[...new Set(missingTargets)].join(', ')}`
        );
      }
      if (figureCount > 1) {
        errors.push(`at most one figure is allowed, found ${figureCount}`);
      }

      return { errors, localTargets };
    }, {
      documentId: manual.documentId,
      heading: manual.heading,
      releaseDate: RELEASE_DATE,
      version: DOCUMENT_VERSION
    });

    validation.errors.push(
      ...(await validateLocalTargets(validation.localTargets, sourcePath))
    );
    for (const target of validation.localTargets) {
      if (target.tagName === 'A') {
        validation.errors.push(
          `local file link would leak a build-host path into the PDF: ${target.rawValue}`
        );
      }
    }
    validation.errors.push(...runtimeErrors);

    if (validation.errors.length > 0) {
      throw new Error(
        `${manual.source} is invalid:\n- ${[...new Set(validation.errors)].join('\n- ')}`
      );
    }

    if (validateOnly) {
      process.stdout.write(
        `Validated: ${path.relative(repositoryRoot, sourcePath)}\n`
      );
      return;
    }

    await page.pdf({
      path: temporaryOutputPath,
      format: 'A4',
      preferCSSPageSize: true,
      printBackground: true,
      displayHeaderFooter: true,
      tagged: true,
      outline: true,
      headerTemplate: `
        <div style="box-sizing:border-box;color:#5b6773;font-family:Arial,sans-serif;
                    font-size:7.5px;padding:0 16mm;width:100%;">
          <span style="float:left;">MyScoutee · ${escapeHtml(manual.title)}</span>
          <span style="float:right;">${manual.documentId} · document version ${DOCUMENT_VERSION}</span>
        </div>`,
      footerTemplate: `
        <div style="box-sizing:border-box;color:#5b6773;font-family:Arial,sans-serif;
                    font-size:7.5px;padding:0 16mm;width:100%;">
          <span style="float:left;">Confidential — Internal Distribution Only · ${RELEASE_DATE} · EN</span>
          <span style="float:right;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
        </div>`
    });

    if (runtimeErrors.length > 0) {
      throw new Error(
        `${manual.source} produced browser errors:\n- `
        + [...new Set(runtimeErrors)].join('\n- ')
      );
    }
    await validatePdf(temporaryOutputPath);
    await fs.rename(temporaryOutputPath, outputPath);
    process.stdout.write(
      `Generated: ${path.relative(repositoryRoot, outputPath)}\n`
    );
  } finally {
    await page.close();
    await fs.rm(temporaryOutputPath, { force: true });
  }
}

async function validateLocalTargets(targets, sourcePath) {
  const errors = [];
  for (const target of targets) {
    let targetPath;
    try {
      targetPath = fileURLToPath(target.url);
    } catch {
      errors.push(
        `invalid local ${target.attribute} target in ${path.basename(sourcePath)}: `
        + target.rawValue
      );
      continue;
    }

    const normalizedPath = path.resolve(targetPath);
    if (plannedOutputPaths.has(normalizedPath)) {
      continue;
    }
    try {
      await fs.access(normalizedPath);
    } catch {
      errors.push(
        `missing local ${target.attribute} target in ${path.basename(sourcePath)}: `
        + target.rawValue
      );
    }
  }
  return errors;
}

async function validatePdf(filePath) {
  const handle = await fs.open(filePath, 'r');
  try {
    const signatureBuffer = Buffer.alloc(5);
    await handle.read(signatureBuffer, 0, signatureBuffer.length, 0);
    if (signatureBuffer.toString('ascii') !== '%PDF-') {
      throw new Error(`generated file does not have a PDF signature: ${filePath}`);
    }
  } finally {
    await handle.close();
  }

  const stats = await fs.stat(filePath);
  if (!stats.isFile() || stats.size < MINIMUM_PDF_BYTES) {
    throw new Error(
      `generated PDF is suspiciously small (${stats.size} bytes): ${filePath}`
    );
  }
}

async function requireAllSources(paths) {
  const missing = [];
  for (const sourcePath of paths) {
    try {
      await fs.access(sourcePath);
    } catch {
      missing.push(path.relative(repositoryRoot, sourcePath));
    }
  }
  if (missing.length > 0) {
    throw new Error(
      'All manual HTML, protocol Markdown, protocol examples, and static '
      + 'assets are required before PDF generation. Missing:\n- '
      + missing.join('\n- ')
    );
  }
}

async function loadPlaywright() {
  const attempts = [];
  const localRequire = createRequire(import.meta.url);
  try {
    return {
      chromium: localRequire('playwright').chromium,
      resolution: 'local project dependency'
    };
  } catch (error) {
    attempts.push(`local project dependency: ${error.code ?? error.message}`);
  }

  const overrideRoot = process.env.DOCS_PLAYWRIGHT_PACKAGE_ROOT;
  if (overrideRoot) {
    const overridePackage = await resolvePackageJson(
      overrideRoot,
      'DOCS_PLAYWRIGHT_PACKAGE_ROOT'
    );
    try {
      const requireFromOverride = createRequire(overridePackage);
      return {
        chromium: requireFromOverride('playwright').chromium,
        resolution: `DOCS_PLAYWRIGHT_PACKAGE_ROOT (${path.dirname(overridePackage)})`
      };
    } catch (error) {
      throw new Error(
        `Playwright is not resolvable from DOCS_PLAYWRIGHT_PACKAGE_ROOT `
        + `(${path.dirname(overridePackage)}): ${error.message}`,
        { cause: error }
      );
    }
  }

  const adjacentPackage = path.resolve(
    repositoryRoot,
    '..',
    'myscoutee-backend',
    'frontend',
    'package.json'
  );
  try {
    await fs.access(adjacentPackage);
    const requireFromAdjacent = createRequire(adjacentPackage);
    return {
      chromium: requireFromAdjacent('playwright').chromium,
      resolution: `adjacent backend frontend (${path.dirname(adjacentPackage)})`
    };
  } catch (error) {
    attempts.push(`adjacent backend frontend: ${error.code ?? error.message}`);
  }

  throw new Error(
    'Unable to load Playwright. Install it locally, or set '
    + 'DOCS_PLAYWRIGHT_PACKAGE_ROOT to a package directory that contains '
    + 'Playwright.\n- '
    + attempts.join('\n- ')
  );
}

async function resolvePackageJson(rawRoot, variableName) {
  const resolvedRoot = path.resolve(rawRoot);
  let stats;
  try {
    stats = await fs.stat(resolvedRoot);
  } catch (error) {
    throw new Error(`${variableName} does not exist: ${resolvedRoot}`, {
      cause: error
    });
  }

  const packageJson = stats.isDirectory()
    ? path.join(resolvedRoot, 'package.json')
    : resolvedRoot;
  if (path.basename(packageJson) !== 'package.json') {
    throw new Error(
      `${variableName} must name a package directory or package.json: ${resolvedRoot}`
    );
  }
  await assertFileExists(packageJson, variableName);
  return packageJson;
}

async function assertFileExists(filePath, label) {
  let stats;
  try {
    stats = await fs.stat(filePath);
  } catch (error) {
    throw new Error(`${label} does not exist: ${filePath}`, { cause: error });
  }
  if (!stats.isFile()) {
    throw new Error(`${label} is not a file: ${filePath}`);
  }
}

async function firstExistingPath(candidates) {
  for (const candidate of candidates) {
    try {
      const stats = await fs.stat(candidate);
      if (stats.isFile()) {
        return candidate;
      }
    } catch {
      // Check the next known browser executable.
    }
  }
  return null;
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
