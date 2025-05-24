#!/usr/bin/env node

const { program } = require('commander');
const inquirer = require('inquirer');
const chalk = require('chalk');
const fs = require('fs-extra');
const path = require('path');
const axios = require('axios');
const { execSync } = require('child_process');

// Config and report storage
const CONFIG_FILE = path.join(process.cwd(), '.dep-audit.json');
const REPORT_FILE = path.join(process.cwd(), 'dependency-audit-report.json');

// Load config
async function loadConfig() {
  try {
    return await fs.readJson(CONFIG_FILE);
  } catch {
    return { ignored: [], allowedLicenses: ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause'] };
  }
}

// Save config
async function saveConfig(config) {
  await fs.writeJson(CONFIG_FILE, config, { spaces: 2 });
  console.log(chalk.green('Configuration saved!'));
}

// Fetch package metadata from npm
async function fetchPackageInfo(name, version) {
  try {
    const response = await axios.get(`https://registry.npmjs.org/${name}`);
    const latest = response.data['dist-tags'].latest;
    const license = response.data.versions[version]?.license || 'Unknown';
    return { latest, license };
  } catch {
    return { latest: 'Unknown', license: 'Unknown' };
  }
}

// Run npm audit
function runNpmAudit() {
  try {
    const audit = execSync('npm audit --json', { encoding: 'utf8' });
    return JSON.parse(audit).vulnerabilities || {};
  } catch {
    return {};
  }
}

// Scan dependencies
async function scanDependencies() {
  const pkg = await fs.readJson(path.join(process.cwd(), 'package.json')).catch(() => ({}));
  const dependencies = { ...pkg.dependencies, ...pkg.devDependencies };
  const config = await loadConfig();
  const vulnerabilities = runNpmAudit();
  const results = [];

  for (const [name, version] of Object.entries(dependencies)) {
    if (config.ignored.includes(name)) continue;

    const { latest, license } = await fetchPackageInfo(name, version);
    const isOutdated = latest !== version && latest !== 'Unknown';
    const hasVulnerability = vulnerabilities[name] ? vulnerabilities[name].severity : null;
    const isLicenseAllowed = config.allowedLicenses.includes(license) || license === 'Unknown';

    results.push({
      name,
      version,
      latest,
      isOutdated,
      hasVulnerability,
      license,
      isLicenseAllowed,
    });
  }

  await fs.writeJson(REPORT_FILE, results, { spaces: 2 });
  console.log(chalk.green(`Audit completed! Report saved to ${REPORT_FILE}`));

  console.log(chalk.cyan('Dependency Audit Summary:'));
  results.forEach(dep => {
    console.log(`- ${dep.name}@${dep.version}`);
    if (dep.isOutdated) console.log(chalk.yellow(`  Outdated: Latest is ${dep.latest}`));
    if (dep.hasVulnerability) console.log(chalk.red(`  Vulnerability: ${dep.hasVulnerability}`));
    if (!dep.isLicenseAllowed) console.log(chalk.red(`  License: ${dep.license} (Not allowed)`));
  });
}

// Check outdated packages
async function checkOutdated() {
  const results = await fs.readJson(REPORT_FILE).catch(() => []);
  const outdated = results.filter(dep => dep.isOutdated);

  if (!outdated.length) {
    console.log(chalk.green('No outdated packages found!'));
    return;
  }

  console.log(chalk.cyan('Outdated Packages:'));
  outdated.forEach(dep => {
    console.log(`${dep.name}: ${dep.version} -> ${dep.latest}`);
  });
}

// Check licenses
async function checkLicenses() {
  const config = await loadConfig();
  const results = await fs.readJson(REPORT_FILE).catch(() => []);
  const nonCompliant = results.filter(dep => !dep.isLicenseAllowed);

  if (!nonCompliant.length) {
    console.log(chalk.green('All licenses are compliant!'));
    return;
  }

  console.log(chalk.cyan('Non-Compliant Licenses:'));
  nonCompliant.forEach(dep => {
    console.log(`${dep.name}: ${dep.license} (Allowed: ${config.allowedLicenses.join(', ')})`);
  });
}

// Update config
async function updateConfig(options) {
  const config = await loadConfig();

  if (options.ignore) {
    config.ignored.push(options.ignore);
    console.log(chalk.green(`Added ${options.ignore} to ignored packages`));
  }

  if (options.addLicense) {
    config.allowedLicenses.push(options.addLicense);
    console.log(chalk.green(`Added ${options.addLicense} to allowed licenses`));
  }

  await saveConfig(config);
}

// Generate report in Markdown
async function generateReport() {
  const results = await fs.readJson(REPORT_FILE).catch(() => []);
  let markdown = '# Dependency Audit Report\n\n';
  markdown += `Generated: ${new Date().toISOString()}\n\n`;

  markdown += '## Summary\n';
  markdown += `- Total Dependencies: ${results.length}\n`;
  markdown += `- Outdated: ${results.filter(d => d.isOutdated).length}\n`;
  markdown += `- Vulnerabilities: ${results.filter(d => d.hasVulnerability).length}\n`;
  markdown += `- Non-Compliant Licenses: ${results.filter(d => !d.isLicenseAllowed).length}\n\n`;

  markdown += '## Details\n';
  results.forEach(dep => {
    markdown += `### ${dep.name}@${dep.version}\n`;
    markdown += `- Latest: ${dep.latest}\n`;
    markdown += `- Vulnerability: ${dep.hasVulnerability || 'None'}\n`;
    markdown += `- License: ${dep.license} (${dep.isLicenseAllowed ? 'Allowed' : 'Not Allowed'})\n\n`;
  });

  await fs.writeFile(path.join(process.cwd(), 'dependency-audit-report.md'), markdown);
  console.log(chalk.green('Markdown report generated!'));
}

program
  .command('scan')
  .description('Scan dependencies for vulnerabilities, outdated packages, and licenses')
  .action(() => scanDependencies());

program
  .command('outdated')
  .description('List outdated packages')
  .action(() => checkOutdated());

program
  .command('licenses')
  .description('Check license compliance')
  .action(() => checkLicenses());

program
  .command('config')
  .description('Update audit configuration')
  .option('--ignore <package>', 'Ignore a package in scans')
  .option('--add-license <license>', 'Add an allowed license')
  .action(options => updateConfig(options));

program
  .command('report')
  .description('Generate a detailed audit report in Markdown')
  .action(() => generateReport());

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
  console.log(chalk.cyan('Use the "scan" command to start auditing dependencies!'));
}
