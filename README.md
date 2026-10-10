
## Detection Rules & Risk Scoring Rubric

### SSH Brute Force Rule
We detect brute-force attacks by grouping normalized events by `source_ip` and checking for **5 or more `login_failure` events within a 5-minute window**.

### Risk Scoring Formula (Deterministic)
Our score is calculated transparently and is clamped to a 0-100 range:
- **Threshold Met:** +40 points
- **Extra Failures:** +5 points per failure above the threshold (capped at +20)
- **Corroborating Success:** +20 points if a successful login occurs after the failures
- **Privileged Activity:** +20 points if a `privilege_change` event follows the failures

### Severity Bands
- **0 - 24:** Low
- **25 - 49:** Medium
- **50 - 74:** High
- **75 - 100:** Critical

## Detection Rules & Risk Scoring Rubric

### SSH Brute Force Rule
We detect brute-force attacks by grouping normalized events by `source_ip` and checking for **5 or more `login_failure` events within a 5-minute window**.

### Risk Scoring Formula (Deterministic)
Our score is calculated transparently and is clamped to a 0-100 range:
- **Threshold Met:** +40 points
- **Extra Failures:** +5 points per failure above the threshold (capped at +20)
- **Corroborating Success:** +20 points if a successful login occurs after the failures
- **Privileged Activity:** +20 points if a `privilege_change` event follows the failures

### Severity Bands
- **0 - 24:** Low
- **25 - 49:** Medium
- **50 - 74:** High
- **75 - 100:** Critical
