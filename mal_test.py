import mailboxes
b= mailboxes.threat_db()
c= mailboxes.alienvault_db()
d= mailboxes.emerging_threat()
a = mailboxes.verify_against_blacklist()
print [x for x in a if x.startswith("Results")]

import malformed_dnscheck
e = malformed_dnscheck.resolve_my_dns()
import time
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
 
doc = SimpleDocTemplate("mal_dns_check.pdf",pagesize=letter,
                        rightMargin=72,leftMargin=72,
                        topMargin=72,bottomMargin=18)

logo = "logo.png"
story = []
im = Image(logo, 2*inch, 2*inch)
story.append(im)
story.append(Spacer(1, 220))

styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY))
ptext = '<font size=12> Report Generated for Host mail.apf.gov.np</font>'

story.append(Paragraph(ptext, getSampleStyleSheet()["Title"]))
story.append(Spacer(1, 290))
ptext1 = '<font size=12>DNS resolver check against threat Intl Database</font>'
story.append(Paragraph(ptext1, getSampleStyleSheet()["Title"]))
story.append(Spacer(1, 12))

for item in e:
    story.append(Paragraph(item, getSampleStyleSheet()["Code"]))

    story.append(Spacer(1, 12))
ptext2 = '<font size=12>Scan report for blacklist check</font>'
story.append(Paragraph(ptext2, getSampleStyleSheet()["Title"]))
story.append(Spacer(1, 12)) 
for item in a:

    story.append(Paragraph(item, getSampleStyleSheet()["Code"]))
    story.append(Spacer(1, 12))
story.append(Spacer(1,12))
thdb= '<font size=12>Scan report for blacklist check online</font>'
story.append(Paragraph(thdb, getSampleStyleSheet()["Title"]))
story.append(Spacer(1,12))
story.append(Paragraph(b, getSampleStyleSheet()["Code"]))
story.append(Spacer(1,12))
aldb= '<font size=12>Scan report for blacklist check Alienvault</font>'
story.append(Paragraph(aldb, getSampleStyleSheet()["Title"]))
story.append(Spacer(1,12))
story.append(Paragraph(c, getSampleStyleSheet()["Code"]))
story.append(Spacer(1,12))
emdb= '<font size=12>Scan report for blacklist check Emerging Threats</font>'
story.append(Paragraph(emdb, getSampleStyleSheet()["Title"]))
story.append(Spacer(1,12))
story.append(Paragraph(d, getSampleStyleSheet()["Code"]))



doc.build(story)





