from datetime import datetime

def generate_report(alerts):
    """
    Generates a professional security audit log in the terminal.
    Handles both simple string alerts and detailed dictionary alerts.
    """
    print("\n" + "="*45)
    print("      🛡️ NETWORK SECURITY AUDIT REPORT")
    print("      Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*45 + "\n")

    if not alerts:
        print(" ✅ STATUS: Normal. No suspicious patterns detected.")
    else:
        # Sort alerts so CRITICAL ones appear at the top of the terminal report
        for alert in alerts:
            if isinstance(alert, dict):
                msg = alert.get("message", "Unknown event")
                score = alert.get("score", 0)
                
                # Assign a visual marker based on the score
                if score >= 80:
                    prefix = " [!] CRITICAL:"
                elif score >= 50:
                    prefix = " [-] WARNING:"
                else:
                    prefix = " [i] INFO:   "
                
                print(f"{prefix} {msg}")
            else:
                # Fallback for simple string-based alerts
                print(f" [?] ALERT:   {alert}")

    print("\n" + "="*45)
    print("      END OF LOG - MONITORING CONTINUES")
    print("="*45 + "\n")