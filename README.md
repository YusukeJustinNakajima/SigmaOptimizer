
# <img src="https://github.com/user-attachments/assets/882178cc-6873-49dd-a725-2c201753b0f7" alt="SigmaOptimizer Logo" width="3.5%"> SigmaOptimizer <br> ~ Automated Sigma Rule Generation and Optimization ~  

## 🎯 Overview  
**SigmaOptimizer** is a **Sigma rule generation and optimization tool** that automatically creates, tests, and improves Sigma rules based on real-world logs.  
It is implemented as a PowerShell script and **integrates log analysis, rule evaluation, and iterative refinement** to enhance detection capabilities.  

✅ **Automated Sigma rule generation**  
✅ **Rule validation with syntax checks (Invoke-SigmaRuleTests)**  
✅ **Detection rate measurement using [Hayabusa](https://github.com/Yamato-Security/hayabusa)**  
✅ **Command obfuscation support ([Invoke-ArgFuscator](https://github.com/wietze/Invoke-ArgFuscator)) for robust detection**  

---

## 📜 Background  
🔹 **LLM-based rule generation often relies solely on user prompts**, leading to **hallucinations** because the model lacks access to real event logs. This results in **shallow and easily bypassed** detection rules.  
🔹 **Rule creation and validation are often separate processes**, meaning even improved rules need to be re-validated manually, which is inefficient.  
🔹 **Creating effective Sigma rules requires a deep understanding of threats.** While it's possible to create rules with limited knowledge, such rules are **easily bypassed by attackers** due to their simplicity.  

---

## ✨ Features  
🔹 **End-to-end rule creation, syntax validation, detection testing, and improvement** in a single workflow.  
🔹 **Log-based rule generation**, rather than relying on user prompts, ensuring rules align with actual system events.  
🔹 **Automated command obfuscation support**, allowing rules to be more resilient against evasion techniques.  

---

## 🚀 Usage  
### 🔧 Prerequisites   
- **Windows environment**  
- **PowerShell 5.1 or later**  
- **OpenAI API Key (Currently, only OpenAI is supported)**  
  - You need to set up an **environment variable** for the API key:  
    ```powershell
    $env:OPENAI_APIKEY = "your_api_key_here"
    ```
- **Required PowerShell Modules**  
  The script depends on the following PowerShell modules:  
  - `Pester` (for running tests)  
  - `powershell-yaml` (for parsing YAML files)  

  Install them using:  
  ```powershell
  Install-Module Pester -Force
  Install-Module powershell-yaml -Force
### 🏁 Execution Steps  
1. **Run the script**  
    ```powershell
    .\SigmaOptimizer.ps1
    ```

2. **Select execution environment**  
    ```
    Choose execution environment (ps for PowerShell, cmd for CMD)
    ```

3. **Enter the command to execute**  
    ```
    Enter the command to execute
    ```

4. **Select Log Source**
    ```
    Select the log sources to use:
    1. Application
    2. Security
    3. System
    4. Microsoft-Windows-Sysmon/Operational
    
    Enter the numbers corresponding to the log sources you want to use, separated by commas (Press Enter for all)::
    ```
    
5. **Review generated Sigma rules**  
    - Rules are saved in `.yml` format under `rules/generate_rules/`.  

6. **Run detection test with Hayabusa**  
    - Enter `y` to execute Hayabusa and validate the rule.  
    ```
    Execute Hayabusa with this Sigma rule? (y/n)
    ```

7. Generate new Sigma Rule based on previous rules
   - Enter y to generate new rules.
    ```
    Generate new Sigma Rule based on previous rules? (y/n):
    ```

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
🔹 **Further optimization of Sigma rule generation**  
🔹 **Development of a GUI interface**  
🔹 **Cloud integration (AWS Lambda / Azure Functions)**  
🔹**Integration with EDR solutions**  

---

SigmaOptimizer **simplifies and automates threat hunting** by enabling efficient rule generation and validation. Try it out to enhance your **Sigma-based detection strategy!** 🚀

