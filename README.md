
# <img src="https://github.com/user-attachments/assets/882178cc-6873-49dd-a725-2c201753b0f7" alt="SigmaOptimizer Logo" width="3.8%"> SigmaOptimizer <br> ~ Automated Sigma Rule Generation and Optimization ~  

## 🎯 Overview  
**SigmaOptimizer** is a **End-to-End Sigma rule generation and optimization tool** that automatically creates, tests, and improves Sigma rules based on real-world logs using **LLM**.  
It is implemented as a PowerShell script and **integrates log analysis, rule evaluation, and iterative refinement** to enhance detection capabilities.  

✅ **Automated Sigma rule generation based on real-world logs**  
✅ **Integration with [MITRE Caldera](https://github.com/mitre/caldera)**  
✅ **Rule validation with syntax checks (Invoke-SigmaRuleTests)**  
✅ **Detection rate measurement using [Hayabusa](https://github.com/Yamato-Security/hayabusa)**  
✅ **FP check of created rules using [evtx-baseline](https://github.com/NextronSystems/evtx-baseline)**  
✅ **Command obfuscation support ([Invoke-ArgFuscator](https://github.com/wietze/Invoke-ArgFuscator)) for robust detection**  

https://github.com/user-attachments/assets/4a637447-1a29-4874-be4e-ee2cc3486310

---

## 📜 Background
🔹 LLM-based Sigma rule creation has inherent limitations. When generating rules solely based on user prompts, without analyzing real-world logs, **hallucinations are more likely to occur.** More importantly, because the rules are not grounded in the actual log events generated by the malicious behavior they aim to detect, they risk being **unreliable and lacking robustness**..  
🔹 **Threat reports are typically published some time after an attack has occurred.** If Sigma rules are created based on these reports, **the time lag may result in incidents** occurring before adequate detection measures are in place. To mitigate this risk, **it is essential to actively execute malware samples and exploited red team tools to generate and refine Sigma rules based on real-world logs.**  
🔹 **Rule creation and validation are often separate processes**, meaning even improved rules need to be re-validated manually, which is inefficient.  
🔹 **Creating effective Sigma rules requires a deep understanding of threats.** While it's possible to create rules with limited knowledge, such rules are **easily bypassed by attackers** due to their simplicity.  

---

## ✨ Features  
🔹 **End-to-end rule creation, syntax validation, detection testing, and improvement** in a single workflow.  
🔹 **Log-based rule generation**, rather than relying on user prompts, ensuring rules align with actual system events.  
🔹 Detection rule creation for **various attack techniques** enabled through integration with **MITRE Caldera.**  
🔹 **Automated command obfuscation support**, allowing rules to be more resilient against evasion techniques.  
🔹 **Reducing hallucinations through multiple validation mechanisms**  

---

## 🚀 Use Cases - Powerful Detection with SigmaOptimizer
### 🔍 Analyze Executable Files & Generate Sigma Rules
- You have obtained a **new malware sample** or a **Red Team tool** (e.g., `mimikatz.exe`)
- Execute the file in a controlled environment, Capture all relevant event logs, Analyze the logs and generate a **custom Sigma rule**

### 🔍 Integration with MITRE Caldera
- Using **MITRE Caldera**, various attack techniques can be selected, and detection rules can be easily created for them.

### 🔍 Detect Malicious Commands (with Obfuscation) & Build Detection Rules
- Input the suspicious command you want to detect(e.g., `certutil /f /urlcache https://www.example.org/ homepage.txt`)
- **Automatically obfuscates the entered command and generates logs.** (Note: Only commands included in the repository's model that support obfuscation are applicable.)
- Capture system logs to understand its behavior, Automatically generate a Sigma rule.

---

## 🚀 Usage  
### 🔧 Prerequisites   
- **Windows environment** 
- **Run `AutoSetup.ps1` to automate the entire setup process. This script handles all the necessary preparations seamlessly. Before executing the script, update the `OPENAI_APIKEY` section in `AutoSetup.ps1` with your own API key.**
    - Installing Required PowerShell Modules
        - `Pester` (for running tests)  
        - `powershell-yaml` (for parsing YAML files)  
        - `Invoke-ArgFuscator` (for command obfuscation) 
    - Downloading and Setting Up Hayabusa
        - The script automatically downloads the latest Hayabusa release from GitHub.
    - Extracting the Archive
        - The script ensures the benign_evtx_logs/win10-client.tgz file is extracted
        - The default setting only checks false positives (FP) using the normal logs obtained in a **Windows 10 client environment.**
        - If needed, add your own logs according to your environment(or use [evtx-baseline](https://github.com/NextronSystems/evtx-baseline))
- **Recommended to configure the following two log sources to create better sigma rules:**
    - Microsoft-Windows-Sysmon/Operational -> Sysmon installation
    - Security EventID:4688 -> https://learn.microsoft.com/ja-jp/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing

### 🏁 Execution Steps
1. **Launch Powershell with administrative privileges**

2. **Run the script**  
    ```powershell
    .\SigmaOptimizer.ps1
    ```

3. **Select execution environment**  
    ```
    Choose execution environment (ps for PowerShell, cmd for CMD, cal for MITRE Caldera):
    ```

4. **If you choose ps or cmd**

    1. **Enter the command to execute**
        ```
        Enter the command to execute
        ```

    2. **Select Log Source**
        ```
        Select the log sources to use:
        1. Application
        2. Security
        3. System
        4. Microsoft-Windows-Sysmon/Operational
        
        Enter the numbers corresponding to the log sources you want to use, separated by commas (Press Enter for all)::
        ```

5. **If you choose cal (When using MITRE Caldera to perform various techniques)**

    1. **Execute MITRE Caldera Operation**
        - Run the agent in the environment where SigmaOptimizer is running.
        - Execute an operation that includes the behavior you want to detect.
        - Note: the implant name should be **splunkd (default name).** Otherwise it will not work.
    
    2. **Confirm MITRE Caldera Operation Completion**
        ```
        Is the MITRE Caldera Operation complete? (y/n):
        ```
    
6. **Review generated Sigma rules**  
    - Rules are saved in `.yml` format under `rules/generate_rules/`.  

7. **Run detection test with Hayabusa**  
    - Enter `y` to execute Hayabusa and validate the rule.  
    ```
    Execute Hayabusa with this Sigma rule? (y/n)
    ```

8. **Generate new Sigma Rule based on previous rules**
   - Enter y to generate new rules.
    ```
    Generate new Sigma Rule based on previous rules? (y/n):
    ```
9. **Check False Positive for normal logs**
    - Enter y to check false positive.
    ```
    Check how much FP is generated by the rules you create? (y/n):
    ```
---
## ✨ Tool Execution Flow 
![diagram (5)](https://github.com/user-attachments/assets/8578d5a5-0276-4fdf-ba8d-0bf571020fa8)

---
## 🤝 Contributing  
We would love to hear your feedback and contributions! 🚀  
If you try **SigmaOptimizer** and have suggestions for improvements, **please submit a pull request or create an issue** on GitHub. Your contributions will help make this tool even better!  

💡 **Ways to contribute:**  
- Report **bugs** or **feature requests** via GitHub Issues 🐛  
- Submit **pull requests** to enhance the rule generation logic 🔧  
- Improve **documentation** or add **new functionalities** 📝  

Your input is greatly appreciated! 🙌

---
## 🔮 Future Work 
🔹 **A machine learning-powered feature that filters distinctive logs to optimize LLM input and avoid rate limits.**   
🔹 **Testing generalization performance (e.g., ensuring that rules created based on two obfuscation patterns also work against other obfuscation patterns).**  
🔹 **Additional syntax checks (e.g., preventing minor mistakes such as using contains instead of contain and automatically correcting small errors in the detection field).**  

---

SigmaOptimizer **simplifies and automates threat hunting, SOC, and forensic** by enabling efficient rule generation and validation. Try it out to enhance your **Sigma-based detection strategy!** 🚀

