"""
tests/detection/mock_data.py

Shared mock forensic-JSON fixtures used across the detection test suite and
for standalone (Member-1-independent) development, as required by the spec.

Each dict follows the mock forensic JSON contract:
subject, body, sender, reply_to, spf, dkim, dmarc, urls, domains,
(optional) display_name, expected_domain, attachments
"""

LEGITIMATE_EMAILS = [
    {
        "subject": "Team lunch next Friday",
        "body": "Hi all, just confirming we're doing team lunch next Friday at 12:30 at the usual place. Let me know if you can't make it.",
        "sender": "sarah.chen@company.com",
        "reply_to": "sarah.chen@company.com",
        "display_name": "Sarah Chen",
        "expected_domain": "company.com",
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "urls": [], "domains": ["company.com"], "attachments": [],
    },
    {
        "subject": "Q3 sprint retro notes",
        "body": "Attaching the notes from today's retro. Nothing urgent, just wanted to share while it's fresh.",
        "sender": "raj.patel@company.com",
        "reply_to": "raj.patel@company.com",
        "display_name": "Raj Patel",
        "expected_domain": "company.com",
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "urls": [], "domains": ["company.com"],
        "attachments": [{"name": "retro-notes.pdf"}],
    },
    {
        "subject": "Your GitHub Actions run succeeded",
        "body": "The workflow 'build-and-test' completed successfully on branch main. View the run for details.",
        "sender": "notifications@github.com",
        "reply_to": "notifications@github.com",
        "display_name": "GitHub",
        "expected_domain": "github.com",
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "urls": ["https://github.com/org/repo/actions/runs/12345"],
        "domains": ["github.com"], "attachments": [],
    },
    {
        "subject": "Newsletter: This month in engineering",
        "body": "Here's a roundup of what shipped this month, plus a couple of blog posts from the team.",
        "sender": "newsletter@company.com",
        "reply_to": "newsletter@company.com",
        "display_name": "Company Engineering",
        "expected_domain": "company.com",
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "urls": ["https://company.com/blog/august-roundup"],
        "domains": ["company.com"], "attachments": [],
    },
    {
        "subject": "Re: Design review feedback",
        "body": "Thanks for the review! I've made the changes you suggested on the second page of the doc.",
        "sender": "maria.lopez@company.com",
        "reply_to": "maria.lopez@company.com",
        "display_name": "Maria Lopez",
        "expected_domain": "company.com",
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "urls": [], "domains": ["company.com"], "attachments": [],
    },
]

PHISHING_EMAILS = [
    {
        "subject": "Your account will be suspended - verify now",
        "body": "We detected unusual activity on your account. Verify your identity immediately to avoid suspension. Click here to confirm your account: login now.",
        "sender": "support@paypa1-secure.com",
        "reply_to": "no-reply@paypa1-secure.com",
        "display_name": "PayPal Security",
        "expected_domain": "paypal.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["http://paypa1-secure.com/verify-login"],
        "domains": ["paypa1-secure.com"], "attachments": [],
    },
    {
        "subject": "URGENT: Password expires today",
        "body": "Your password expires today. Confirm your identity and reset your password immediately by clicking the secure link below.",
        "sender": "it-support@company-portal-login.xyz",
        "reply_to": "it-support@company-portal-login.xyz",
        "display_name": "IT Support",
        "expected_domain": "company.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["http://198.51.100.23/reset-password-verify"],
        "domains": ["company-portal-login.xyz"], "attachments": [],
    },
    {
        "subject": "Unusual sign-in activity detected",
        "body": "We noticed a sign-in from a new device. If this wasn't you, verify your account immediately or it will be suspended within 24 hours.",
        "sender": "security-alert@0ffice365-verify.top",
        "reply_to": "security-alert@0ffice365-verify.top",
        "display_name": "Microsoft Account Team",
        "expected_domain": "microsoft.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["https://bit.ly/3verify365"],
        "domains": ["0ffice365-verify.top"], "attachments": [],
    },
    {
        "subject": "Your Netflix payment failed",
        "body": "We were unable to process your payment. Update your billing details now to avoid losing access to your account.",
        "sender": "billing@netflix-account-support.click",
        "reply_to": "billing@netflix-account-support.click",
        "display_name": "Netflix",
        "expected_domain": "netflix.com",
        "spf": "fail", "dkim": "none", "dmarc": "fail",
        "urls": ["http://netflix-account-support.click/update-billing-login"],
        "domains": ["netflix-account-support.click"], "attachments": [],
    },
    {
        "subject": "Document shared with you - action required",
        "body": "A secure document has been shared with you. Click here to sign in and view it before the link expires.",
        "sender": "docusign@docus1gn-notify.work",
        "reply_to": "docusign@docus1gn-notify.work",
        "display_name": "DocuSign",
        "expected_domain": "docusign.net",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["http://docus1gn-notify.work/view?id=1"],
        "domains": ["docus1gn-notify.work"], "attachments": [],
    },
]

BEC_EMAILS = [
    {
        "subject": "URGENT PAYMENT REQUIRED",
        "body": "I need you to process a wire transfer immediately to a new vendor before end of day. This is time-sensitive and confidential, please don't discuss with anyone else on the team. Reply directly to me here.",
        "sender": "ceo@fake-company.com",
        "reply_to": "random@gmail.com",
        "display_name": "John Smith",
        "expected_domain": "company.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["https://fake-login.example"],
        "domains": ["fake-company.com"], "attachments": [],
    },
    {
        "subject": "Quick favor - need gift cards",
        "body": "Hi, are you at your desk? I need you to purchase gift cards for a client right away, it's urgent. I'm in a meeting and can't talk right now, just reply to this email once done.",
        "sender": "ceo.office@company-corp.com",
        "reply_to": "ceo.office@company-corp.com",
        "display_name": "CEO Office",
        "expected_domain": "company.com",
        "spf": "fail", "dkim": "none", "dmarc": "fail",
        "urls": [], "domains": ["company-corp.com"], "attachments": [],
    },
    {
        "subject": "Update vendor bank details ASAP",
        "body": "Please update the bank account details for our vendor invoice and process the payment today. This comes directly from management, keep this between us until it's done.",
        "sender": "cfo@compnay.com",
        "reply_to": "cfo.finance@outlook.com",
        "display_name": "CFO Finance",
        "expected_domain": "company.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": [], "domains": ["compnay.com"], "attachments": [],
    },
]

IMPERSONATION_EMAILS = [
    {
        "subject": "Following up on our conversation",
        "body": "As discussed, please send over the requested files when you get a chance. Let me know if you have questions.",
        "sender": "ceo@fake-company-login.com",
        "reply_to": "ceo@fake-company-login.com",
        "display_name": "CEO John",
        "expected_domain": "company.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": [], "domains": ["fake-company-login.com"], "attachments": [],
    },
    {
        "subject": "Quick task before my flight",
        "body": "I'm about to board and can't talk right now, but I need you to handle this quietly for me. Reach me only by email until I land.",
        "sender": "jane.director@compahy.com",
        "reply_to": "jane.director@compahy.com",
        "display_name": "Jane Director",
        "expected_domain": "company.com",
        "spf": "none", "dkim": "fail", "dmarc": "fail",
        "urls": [], "domains": ["compahy.com"], "attachments": [],
    },
    {
        "subject": "Vendor contact update",
        "body": "Please note our accounts payable contact has changed. Direct future correspondence to this address going forward.",
        "sender": "ap@acme-supp1ies.com",
        "reply_to": "ap@acme-supp1ies.com",
        "display_name": "Acme Supplies AP",
        "expected_domain": "acme-supplies.com",
        "spf": "none", "dkim": "fail", "dmarc": "none",
        "urls": [], "domains": ["acme-supp1ies.com"], "attachments": [],
    },
]

FRAUD_EMAILS = [
    {
        "subject": "Revised invoice - updated payment details",
        "body": "Please find attached the revised invoice. Note that our bank account details have changed, kindly update your records and process payment to the new account before the due date.",
        "sender": "accounts@longtime-vendor.com",
        "reply_to": "accounts.payable@vendor-mail.com",
        "display_name": "Accounts Receivable",
        "expected_domain": "longtime-vendor.com",
        "spf": "fail", "dkim": "none", "dmarc": "fail",
        "urls": [], "domains": ["longtime-vendor.com"],
        "attachments": [{"name": "invoice_updated.pdf"}],
    },
    {
        "subject": "Congratulations - you've won a prize",
        "body": "You have been selected to receive a cash prize of $50,000. To claim it, reply with your bank account and routing number within 48 hours.",
        "sender": "claims@lottery-rewards-intl.top",
        "reply_to": "claims@lottery-rewards-intl.top",
        "display_name": "International Lottery Board",
        "expected_domain": None,
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": [], "domains": ["lottery-rewards-intl.top"], "attachments": [],
    },
]

MALWARE_EMAILS = [
    {
        "subject": "Your invoice is attached",
        "body": "Please find your invoice attached. Open the attachment and enable content to view the details.",
        "sender": "billing@shipping-notice-alerts.top",
        "reply_to": "billing@shipping-notice-alerts.top",
        "display_name": "Billing Department",
        "expected_domain": None,
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": [],
        "domains": ["shipping-notice-alerts.top"],
        "attachments": [{"name": "invoice_08_2026.zip"}],
    },
]

ALL_MOCK_EMAILS = {
    "legitimate": LEGITIMATE_EMAILS,
    "phishing": PHISHING_EMAILS,
    "bec": BEC_EMAILS,
    "impersonation": IMPERSONATION_EMAILS,
    "fraud": FRAUD_EMAILS,
    "malware": MALWARE_EMAILS,
}
