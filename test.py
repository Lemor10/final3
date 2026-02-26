from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os

message = Mail(
    from_email='dogrnw2026@gmail.com',
    to_emails='romeldiazlachica@gmail.com',
    subject='Test Email',
    html_content='<strong>Hello from SendGrid!</strong>'
)

try:
    sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
    response = sg.send(message)
    print("Status:", response.status_code)
    print("Body:", response.body)
    print("Headers:", response.headers)
except Exception as e:
    print("Error:", e)