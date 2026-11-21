LetsDefend – Learn Sigma Lab

1. Lab Overview

Item| Details
Platform| LetsDefend
Lab| Learn Sigma
Category| Blue Team
Focus| Sigma Rule Analysis
Status| Completed

2. Scenario

The organization detected a ransomware infection affecting one of its critical systems.

The investigation revealed that the ransomware may have abused the legitimate Windows utility "bitsadmin.exe" to download malicious payloads or communicate with its Command and Control (C2) server.

The objective was to analyze a Sigma detection rule and understand how its detection logic identifies suspicious Bitsadmin activity.

3. Investigation Summary

The analyzed Sigma rule:

"proc_creation_win_bitsadmin_download.yml"

Key findings:

- Log Source: Windows
- Event Category: "process_creation"
- Target Process: "bitsadmin.exe"
- Detection Focus: Suspicious command-line arguments associated with file transfers and HTTP activity.
- Captured Field: "CommandLine"
- MITRE ATT&CK: Defense Evasion

Detection Condition

condition: selection_img and (selection_cmd or all of selection_cli_*)

The rule combines process identification with command-line criteria to detect suspicious Bitsadmin execution.

4. Questions & Answers

Q1. Which executable file was specifically targeted by this Sigma rule?

Answer: "bitsadmin.exe"

Evidence:

<img width="694" height="438" alt="Screenshot 2026-11-21 131836" src="https://github.com/user-attachments/assets/f63ada6f-070e-4880-892f-ac3ca6fc3ddb" />


---

Q2. What command-line option is used to indicate a file transfer?

Answer: "/transfer"

Evidence:

<img width="1083" height="857" alt="photo_2026-11-21_13-51-45" src="https://github.com/user-attachments/assets/83f56910-ba92-4466-9cd7-b88926e4771a" />


---

Q3. What logical expression combines the criteria to trigger this rule?

Answer:

selection_img and (selection_cmd or all of selection_cli_*)

Evidence:

<img width="586" height="265" alt="Screenshot 2026-11-21 131951" src="https://github.com/user-attachments/assets/ffc46a8b-6843-4ec1-9b69-9afc63d77460" />


---

Q4. Which specific field captures the command being executed?

Answer: "CommandLine"

Evidence:

<img width="440" height="261" alt="Screenshot 2026-11-21 132407" src="https://github.com/user-attachments/assets/cc65567a-e91a-4bfe-915a-9d3848a47b6a" />


---

Q5. Which single ATT&CK tactic tag is listed first in this rule?

Answer: "attack.defense-evasion"

Evidence:

<img width="484" height="254" alt="Screenshot 2026-11-21 132502" src="https://github.com/user-attachments/assets/f5a35d2d-e199-46f2-9abc-a2f7b4465d53" />


---

Q6. What is the primary category of events that this Sigma rule was written to monitor?

Answer: "process_creation"

Evidence:

<img width="415" height="179" alt="Screenshot 2026-11-21 133418" src="https://github.com/user-attachments/assets/e51a7064-f49a-413b-8024-2e815be75b9d" />


---

Q7. What specific command-line argument did this rule look for to identify HTTP-based downloads?

Answer: "http"

Evidence:

<img width="511" height="137" alt="Screenshot 2026-11-21 133528" src="https://github.com/user-attachments/assets/84971c62-2870-4965-9d7d-fcfafc86058b" />

---

Q8. Which command-line option must be present to create a new transfer using Bitsadmin?

Answer: "/create"

Evidence:

<img width="529" height="339" alt="Screenshot 2026-11-21 133555" src="https://github.com/user-attachments/assets/97d6c379-c494-4946-abeb-0d3994061721" />


---

5. Key Takeaways

- Understanding Sigma rule structure and detection logic.
- Identifying suspicious use of legitimate Windows utilities (LOLBins).
- Analyzing Windows process creation events.
- Understanding command-line based detection.
- Mapping detection rules to MITRE ATT&CK.
- Recognizing potentially malicious Bitsadmin file transfer activity.

6. Conclusion

Successfully completed the LetsDefend Learn Sigma lab.

This lab improved my ability to analyze Sigma detection rules, understand selection and condition logic, and identify suspicious Windows process execution through command-line analysis.

Skills: Sigma | Detection Engineering | Windows Process Analysis | MITRE ATT&CK | LOLBins | Blue Team
