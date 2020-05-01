import re

from bs4 import BeautifulSoup

from tor import urlget

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College, template_environment


class VCC(College):
    short_name = "VCC"
    name = "Ventura College"
    icon = "images/vcc.png"

    renewal_period = "quarter"
    renewal_cost = 5

    search_req = urlget("https://ssb.vcccd.edu/prod/pw_pub_sched.P_Simple_SEARCH")

    search_page = BeautifulSoup(search_req.text, "html.parser")

    term_options = search_page.find("select", attrs={"name": "term"}).findChildren("option")

    terms = []
    for option in term_options:
        terms.append((option["value"], option.string))

    add_template_params = {"terms": terms}

    add_template = template_environment.get_template("vcc/VCC.html")

    PATTERN_CRN = re.compile(r"[0-9]{5}")

    @staticmethod
    def verify_add_request(form):
        term = form.get("term")
        crn = form.get("crn")
        if term is None:
            return errors("Term is missing", "class_add")
        if crn is None:
            return errors("CRN is missing", "class_add")
        if term not in (term[0] for term in VCC.terms):
            return errors("Invalid term", "class_add")
        if not VCC.PATTERN_CRN.match(crn):
            return errors("Invalid CRN", "class_add")
        return True

    @staticmethod
    def monitor_from_add_request(form):
        crn = form.get("crn")
        term = form.get("term")
        sub = form.get("sub")
        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, VCC.Class) \
                    and c.vcrn == crn \
                    and c.vterm == term \
                    and c.vsub == sub:
                return monitor

        class_instance = VCC.Class(crn, term, sub)
        class_monitor = ClassMonitor(VCC.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        base_url = "https://ssb.vcccd.edu/prod/pw_pub_sched"
        PATTERN_AVAIL = re.compile(r"<td class=\"default3\">(-?\d*)</td>")

        def __init__(self, crn, term, sub):
            super().__init__()
            self.url = VCC.Class.base_url + ".p_course_popup?vsub={}&vterm={}&vcrn={}".format(sub, term, crn)
            html = urlget(self.url).text
            self.vcrn = crn
            self.vterm = term
            self.vsub = sub
            self.total_normal_seats = 0
            self.normal_seats_avail = 0
            self.total_waitlist_seats = 0
            self.waitlist_seats_avail = 0

            self.display_name = "{} (CRN: {})".format(self.vsub, self.vcrn)
            self.status_message = "VCC Status"
            self.info_url = VCC.Class.base_url + ".p_course_popup?vsub={}&vterm={}&vcrn={}".format(self.vsub,
                                                                                                   self.vterm,
                                                                                                   self.vcrn)
            self.action_url = "https://account.vcccd.edu/_layouts/PG/login.aspx"
            self.update_status()

        def update_status(self):
            html = urlget(self.url).text
            a = VCC.Class.PATTERN_AVAIL.findall(html)
            self.total_normal_seats = int("".join(a[0]))
            self.normal_seats_avail = int("".join(a[2]))
            self.total_waitlist_seats = int("".join(a[3]))
            self.waitlist_seats_avail = int("".join(a[5]))
            self.status_message = "Seats Taken: {} / {} | Waitlist: {} / {}".format(
                self.total_normal_seats - self.normal_seats_avail,
                self.total_normal_seats,
                self.total_waitlist_seats - self.waitlist_seats_avail,
                self.total_waitlist_seats)
            if self.total_waitlist_seats == 0:
                self.has_availability = self.normal_seats_avail > 0
            else:
                self.has_availability = self.waitlist_seats_avail > 0

            return self.has_availability

        def __str__(self):
            return "<VCC {}>".format(self.display_name)
