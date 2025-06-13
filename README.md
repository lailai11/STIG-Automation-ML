# STIG-Automation-ML

## AI-Powered DISA STIG Compliance Assistant

### Overview

`STIG-Automation-ML` is an ambitious project aimed at revolutionizing the process of reviewing and applying DISA Security Technical Implementation Guides (STIGs). Leveraging the power of Python, Artificial Intelligence (AI), and Machine Learning (ML), this tool seeks to automate manual compliance checks, generate actionable findings, and produce preliminary Plans of Action & Milestones (POA&Ms) for non-compliant items.

Traditionally, STIG compliance involves extensive manual checks, even with automated SCAP scans. This project directly addresses that administrative burden by building a smart, automated assistant capable of interpreting STIG requirements and assessing system configurations.

### Problem Solved

* **Reduces Manual Effort:** Automates time-consuming manual STIG checks.
* **Accelerates Compliance:** Speeds up the identification of non-compliant items.
* **Streamlines Reporting:** Automatically generates detailed findings and initial POA&Ms.
* **Enhances Accuracy:** Reduces human error in the review process.

### Features (In Progress / Planned)

* **STIG Content Parsing:** Programmatically extracts detailed rules, check procedures, and fix texts from DISA STIG XCCDF XML files. (Completed for Windows 11).
* **Custom Compliance Check Engine:** Implements Python-based functions to perform granular system-level checks based on STIG requirements (e.g., registry values, service states, file permissions, system information). (Initial checks implemented for Windows 11).
* **AI/ML-Powered Finding Generation (Future):** Utilize Large Language Models (LLMs) to generate clear, concise, and context-aware findings for non-compliant items, based on the `Check Content` and system output.
* **Automated POA&M Creation (Future):** Generate preliminary POA&M entries including affected system, finding, remediation plan, and suggested milestones.
* **Interactive Dashboard (Future):** A user-friendly web application (likely built with Streamlit) to upload system data, visualize compliance posture, review findings, and manage POA&Ms.

### Technologies Used

* **Python 3.x:** The primary programming language for all logic and AI/ML components.
* **`xml.etree.ElementTree`:** Python's built-in XML parser for handling XCCDF STIG files.
* **`subprocess`:** For executing system commands (e.g., PowerShell cmdlets, `cmd.exe` commands) to perform compliance checks.
* **`winreg`:** Python's built-in module for direct interaction with the Windows Registry.
* **Streamlit (Future):** For building the interactive web dashboard.
* **Machine Learning Libraries (Future):** Potentially Hugging Face Transformers (for LLMs), scikit-learn, pandas, numpy for data processing and model training.
* **Git & GitHub:** For version control and collaborative development.

### Project Structure
Coding partner

Show thinking
Great idea! Before we add more code, it's an excellent practice to commit your current progress to GitHub. This keeps your project history clean and ensures your work is backed up.

After that, crafting a "good-looking" README.md is absolutely essential for a portfolio project. It's often the very first thing a potential employer or collaborator sees, and it acts as your project's resume.

Step 1: Commit windows_checker.py to GitHub
Open your terminal or Git Bash.

Navigate to the root directory of your STIG-Automation-ML project.

Bash

cd D:\STIG-Automation-ML
Check the status of your files:

Bash

git status
You should see src/windows_checker.py listed as a new, untracked file (likely in red).

Add the new file to the staging area:

Bash

git add src/windows_checker.py
(Or git add . to add all new/modified files, including the new windows_checker.py).

Commit your changes:

Bash

git commit -m "Add initial Windows 11 custom compliance checker with sample rules"
This commit message is descriptive and explains what was added.

Push your changes to GitHub:

Bash

git push origin main
(Confirm your branch name is main).

After these steps, refresh your STIG-Automation-ML repository on GitHub. You should now see the src/windows_checker.py file in your repository!

Step 2: Create a Good-Looking README.md
Now, let's create a compelling README.md for your project. This file is located in the root of your repository (D:\STIG-Automation-ML\README.md).

Open the README.md file in your code editor and replace its existing content with the following. This README is designed to be comprehensive and professional, showcasing your project's value.

Markdown

# STIG-Automation-ML

## AI-Powered DISA STIG Compliance Assistant

### Overview

`STIG-Automation-ML` is an ambitious project aimed at revolutionizing the process of reviewing and applying DISA Security Technical Implementation Guides (STIGs). Leveraging the power of Python, Artificial Intelligence (AI), and Machine Learning (ML), this tool seeks to automate manual compliance checks, generate actionable findings, and produce preliminary Plans of Action & Milestones (POA&Ms) for non-compliant items.

Traditionally, STIG compliance involves extensive manual checks, even with automated SCAP scans. This project directly addresses that administrative burden by building a smart, automated assistant capable of interpreting STIG requirements and assessing system configurations.

### Problem Solved

* **Reduces Manual Effort:** Automates time-consuming manual STIG checks.
* **Accelerates Compliance:** Speeds up the identification of non-compliant items.
* **Streamlines Reporting:** Automatically generates detailed findings and initial POA&Ms.
* **Enhances Accuracy:** Reduces human error in the review process.

### Features (In Progress / Planned)

* **STIG Content Parsing:** Programmatically extracts detailed rules, check procedures, and fix texts from DISA STIG XCCDF XML files. (Completed for Windows 11).
* **Custom Compliance Check Engine:** Implements Python-based functions to perform granular system-level checks based on STIG requirements (e.g., registry values, service states, file permissions, system information). (Initial checks implemented for Windows 11).
* **AI/ML-Powered Finding Generation (Future):** Utilize Large Language Models (LLMs) to generate clear, concise, and context-aware findings for non-compliant items, based on the `Check Content` and system output.
* **Automated POA&M Creation (Future):** Generate preliminary POA&M entries including affected system, finding, remediation plan, and suggested milestones.
* **Interactive Dashboard (Future):** A user-friendly web application (likely built with Streamlit) to upload system data, visualize compliance posture, review findings, and manage POA&Ms.

### Technologies Used

* **Python 3.x:** The primary programming language for all logic and AI/ML components.
* **`xml.etree.ElementTree`:** Python's built-in XML parser for handling XCCDF STIG files.
* **`subprocess`:** For executing system commands (e.g., PowerShell cmdlets, `cmd.exe` commands) to perform compliance checks.
* **`winreg`:** Python's built-in module for direct interaction with the Windows Registry.
* **Streamlit (Future):** For building the interactive web dashboard.
* **Machine Learning Libraries (Future):** Potentially Hugging Face Transformers (for LLMs), scikit-learn, pandas, numpy for data processing and model training.
* **Git & GitHub:** For version control and collaborative development.

### Project Structure

STIG-Automation-ML/
├── data/
│   ├── raw/                  # Stores raw STIG XML files
│   └── processed/            # Stores processed data
├── src/
│   ├── utils/
│   │   └── xccdf_parser.py   # Script to parse XCCDF XML files
│   ├── checks/
│   │   └── windows_checker.py # Contains Windows-specific compliance checks
│   ├── models/               # Stores trained AI/ML models
│   └── init.py           # Makes src a Python package
├── app/
│   └── main_app.py           # Streamlit dashboard application code
├── notebooks/                # Jupyter notebooks for exploration
├── .gitignore                # Untracked files to ignore
└── README.md                 # Project overview and documentation

### Getting Started

To get a copy of the project up and running on your local machine for development and testing:

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/lailai11/STIG-Automation-ML.git](https://github.com/lailai11/STIG-Automation-ML.git)
    cd STIG-Automation-ML
    ```

2.  **Create and activate a virtual environment** (recommended):
    ```bash
    python -m venv venv
    # On Windows:
    .\venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    Currently, only built-in Python modules are used for parsing, but you may want to install `psutil` if you plan more extensive system checks:
    ```bash
    pip install psutil
    ```
    (Future dependencies like `streamlit`, `transformers`, etc., will be added as features are developed).

4.  **Place your STIG XML file:**
    Download the `U_MS_Windows_11_STIG_V2R3_Manual-xccdf.xml` (or similar XCCDF file) from a trusted source like the DoD Cyber Exchange and place it in the `data/raw/` directory.

5.  **Run the STIG Parser:**
    Execute the XCCDF parser to verify data extraction:
    ```bash
    python src/utils/xccdf_parser.py
    ```
    This should output a summary of parsed rules.

6.  **Run the Windows Checker (requires Administrator privileges):**
    Execute the initial compliance checks:
    ```bash
    # Open your terminal/PowerShell 'as Administrator'
    python src/windows_checker.py
    ```
    This will perform the implemented checks and display their compliance status.

### Future Enhancements

* **Expand Custom Checks:** Implement automated checks for a wider range of STIG categories (e.g., auditing, user rights, software configurations).
* **AI/ML Integration:** Develop and integrate NLP models for intelligent finding generation and POA&M drafting.
* **Streamlit Dashboard:** Build an interactive user interface for a complete compliance workflow.
* **Cross-Platform Compatibility:** Extend checks to other operating systems (e.g., Linux STIGs).
* **Reporting:** Generate formal compliance reports.

### Usage Examples (Future)

* **`python main.py --scan windows11`**: Run a full compliance scan on Windows 11.
* **`streamlit run app/main_app.py`**: Launch the interactive compliance dashboard.
* **`python ml_model.py --train`**: Train the AI model for generating findings.

### Contributing

Contributions are welcome! If you have suggestions for new features, improvements, or bug fixes, please open an issue or submit a pull request.

### License

This project is licensed under the MIT License - see the `LICENSE` file for details.

### Contact

For any questions or feedback, please feel free to reach out via GitHub issues.