# Data Policy

_Last updated: July 17, 2025_

## Overview

This project may process user data as part of its functionality (e.g., scanning source code for vulnerabilities). This document outlines our data handling practices, including what is collected, how it is used, and your responsibilities as a user.

## 1. Data Collection

This project **does not collect, transmit, or store** any user data externally. All scanning and analysis are performed locally within your GitHub Actions environment or system.

## 2. Data Usage

Any data processed by this project (e.g., source code, configuration files) is used solely for the purpose of:

- Performing static analysis or scanning for vulnerabilities.
- Generating results (logs, reports) within your CI/CD pipeline or local environment.

No user data is sent to any third-party service or retained outside your infrastructure.

## 3. Third-Party Tools

If this project integrates with third-party tools (e.g., Trivy, AST-Grep), please refer to their respective privacy policies to understand how they handle data.

## 4. User Responsibilities

As a user of this project, you are responsible for:

- Ensuring that you do not upload sensitive or private data to public repositories.
- Complying with your organization's data protection policies.
- Reviewing and understanding how any external tools or APIs used with this project handle data.

## 5. Disclaimer of Liability

This project is provided **"as-is"**, without warranty of any kind. The authors and maintainers are **not liable** for any damages, data loss, or security issues resulting from the use of this software.

By using this project, you agree to use it **at your own risk**.

## 6. Changes to This Policy

We may update this policy from time to time. Changes will be committed to this repository with an updated timestamp.

---

For questions or concerns regarding this data policy, please open an issue in the repository.