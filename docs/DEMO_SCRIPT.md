# Judge Demo Script (3 Minutes)

**0:00 - Intro (Member 4)**
"Hi, we are SledgeAuth. SOC analysts are overwhelmed by alerts. We built an AI Copilot that ingests Linux auth logs, detects threats deterministically, and provides evidence-grounded AI guidance."

**0:30 - Normal Log (Member 1)**
*Show Streamlit UI with normal_auth.log loaded*
"First, we upload a normal log. Notice the dashboard shows zero alerts. Our detection doesn't false-positive on normal logins."

**1:00 - Suspicious Log (Member 2)**
*Show Streamlit UI with suspicious_auth.log loaded*
"Now we upload a suspicious log. Our detection module groups events by IP and detects 6 failed SSH logins from `203.0.113.25` in 5 minutes. 
Notice the **risk score of 45**. This isn't hard-coded. It's calculated mathematically: +40 for the threshold, +5 for the extra failure. This maps to a Medium severity."

**1:45 - AI Copilot (Member 3)**
*Click into the alert details*
"We pass this structured evidence to our AI Copilot. It returns a summary, a checklist, and recommended disposition. Notice it clearly labels this as AI-generated analysis and never invents facts beyond the evidence we supplied."

**2:15 - Analyst Control (Member 4)**
*Show the status dropdown*
"Finally, the analyst is always in control. We can set the status to 'Investigating' or 'Escalated'. The system never takes automated response actions."

**2:30 - Wrap Up**
"Everything you saw was built in 24 hours. Our code is fully tested, modular, and ready to scale."
