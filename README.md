# 📌 SigmaOptimizer<br> - Automated Sigma Rule Optimization 🚀  

## 🎯 Overview  
**SigmaOptimizer** is a **Sigma rule generation and optimization tool** that automatically creates, tests, and improves Sigma rules based on real-world logs.  
It is implemented as a PowerShell script and **integrates log analysis, rule evaluation, and iterative refinement** to enhance detection capabilities.  

✅ **Automated Sigma rule generation**  
✅ **Rule validation with syntax checks (Invoke-SigmaRuleTests)**  
✅ **Detection rate measurement using Hayabusa**  
✅ **Command obfuscation support (Invoke-ArgFuscator) for robust detection**  

---

## 📜 Background  
🔹 **LLM-based rule generation often relies solely on user prompts**, leading to **hallucinations** because the model lacks access to real event logs. This results in **shallow and easily bypassed** detection rules.  
🔹 **Rule creation and validation are often separate processes**, meaning even improved rules need to be re-validated manually, which is inefficient.  

---

## ✨ Features  
💡 **End-to-end rule creation, syntax validation, detection testing, and improvement** in a single workflow.  
📂 **Log-based rule generation**, rather than relying on user prompts, ensuring rules align with actual system events.  
🔄 **Automated command obfuscation support**, allowing rules to be more resilient against evasion techniques.  

---

## 🚀 Usage  
### 🔧 Prerequisites  
- Windows environment  
- PowerShell 5.1 or later  
- Required modules: `OpenAI_SigmaModule.psm1`, `SigmaRuleTests.psm1`, `Invoke-ArgFuscator`  

### 🏁 Execution Steps  
1. **Import required modules**  
    ```powershell
    Import-Module .\OpenAI_SigmaModule.psm1 -Force
    Import-Module .\SigmaRuleTests.psm1 -Force
    Import-Module Invoke-ArgFuscator
    ```

2. **Run the script**  
    ```powershell
    .\SigmaOptimizer.ps1
    ```

3. **Select execution environment**  
    ```
    Choose execution environment (ps for PowerShell, cmd for CMD)
    ```

4. **Enter the command to execute**  
    ```
    Enter the command to execute
    ```

5. **Review generated Sigma rules**  
    - Rules are saved in `.yml` format under `rules/generate_rules/`.  

6. **Run detection test with Hayabusa**  
    - Enter `y` to execute Hayabusa and validate the rule.  
    ```
    Execute Hayabusa with this Sigma rule? (y/n)
    ```

7. **Review results**  
    - The final detection report is saved in `detection_result.txt`.  

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
🛠 **Further optimization of Sigma rule generation**  
📊 **Development of a GUI interface**  
⚡ **Cloud integration (AWS Lambda / Azure Functions)**  
🛡 **Integration with EDR solutions**  

---

SigmaOptimizer **simplifies and automates threat hunting** by enabling efficient rule generation and validation. Try it out to enhance your **Sigma-based detection strategy!** 🚀

