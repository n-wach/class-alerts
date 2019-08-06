import re

from tor import urlget

from jinja2 import Template

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College


class SBCC(College):
    short_name = "SBCC"
    name = "Santa Barbara City College"
    icon = "images/sbcc.jpg"

    terms = [("202030", "Fall 2019")]

    add_template_params = {"terms": terms}

    with open('colleges/sbcc/SBCC.html') as file_:
        add_template = Template(file_.read())

    PATTERN_CRN = re.compile(r"[0-9]{5}")

    @staticmethod
    def verify_add_request(form):
        term = form.get("term")
        crn = form.get("crn")
        if term is None:
            return errors("Term is missing", "class_add")
        if crn is None:
            return errors("CRN is missing", "class_add")
        if term not in SBCC.terms:
            return errors("Invalid term", "class_add")
        if not SBCC.PATTERN_CRN.match(crn):
            return errors("Invalid CRN", "class_add")
        return True

    @staticmethod
    def monitor_from_add_request(form):
        crn = form.get("crn")
        term = form.get("term")
        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, SBCC.Class) \
                    and c.vcrn == crn \
                    and c.vterm == term:
                return monitor

        class_instance = SBCC.Class(crn, term)
        class_monitor = ClassMonitor(SBCC.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        base_url = "https://banner.sbcc.edu/PROD/pw_pub_sched"
        PATTERN_AVAIL = re.compile(r"<td class=\"default3\">(-?\d*)</td>")
        PATTERN_VSUB = re.compile(r"(dept=)([A-z]+)")
        PATTERN_VCRSE = re.compile(r"(course=)(\d+)")

        def __init__(self, crn, term):
            super().__init__()
            self.url = SBCC.Class.base_url + ".p_course_popup?vterm={}&vcrn={}".format(term, crn)
            html = urlget(self.url).text
            self.vcrn = crn
            self.vterm = term
            self.vsub = SBCC.Class.PATTERN_VSUB.search(html).group(2)
            self.vcrse = SBCC.Class.PATTERN_VCRSE.search(html).group(2)
            self.total_normal_seats = 0
            self.normal_seats_avail = 0
            self.total_waitlist_seats = 0
            self.waitlist_seats_avail = 0

            self.display_name = "%s %s (CRN: %s)" % (self.vsub, self.vcrse, self.vcrn)
            self.status_message = "SBCC Status"
            self.info_url = SBCC.Class.base_url + ".p_course_popup?vsub={}&vcrse={}&vterm={}&vcrn={}".format(self.vsub,
                                                                                                             self.vcrse,
                                                                                                             self.vterm,
                                                                                                             self.vcrn)
            self.update_status()

        def update_status(self):
            html = urlget(self.url).text
            a = SBCC.Class.PATTERN_AVAIL.findall(html)
            self.total_normal_seats = int("".join(a[0]))
            self.normal_seats_avail = int("".join(a[2]))
            self.total_waitlist_seats = int("".join(a[3]))
            self.waitlist_seats_avail = int("".join(a[5]))
            self.status_message = "Seats Taken: %d of %d | Waitlist Spots Taken: %d of %d" \
                                  % (self.total_normal_seats - self.normal_seats_avail, self.total_normal_seats,
                                     self.total_waitlist_seats - self.waitlist_seats_avail, self.total_waitlist_seats)
            if self.total_waitlist_seats == 0:
                self.has_availability = self.normal_seats_avail > 0
            else:
                self.has_availability = self.waitlist_seats_avail > 0

            return self.has_availability

        def __str__(self):
            return "<SBCC {}>".format(self.display_name)
