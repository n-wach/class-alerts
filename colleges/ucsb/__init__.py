import re
from urllib.request import urlopen

from jinja2 import Template

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College


class UCSB(College):
    short_name = "UCSB"
    name = "University of California Santa Barbara"
    icon = "images/ucsb.jpg"

    years = ["2019"]
    term_names = ["Spring", "Fall"]
    codes = ["LEC", "SEM"]

    add_template_params = {"years": years, "term_names": term_names, "codes": codes}

    with open('colleges/ucb/Berkeley.html') as file_:
        add_template = Template(file_.read())

    PATTERN_CRN = re.compile(r"[0-9]{5}")
    PATTERN_TERM = re.compile(r"[0-9]{6}")

    @staticmethod
    def verify_add_request(request):
        term = request.form.get("term")
        crn = request.form.get("crn")
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
    def monitor_from_add_request(request):
        crn = request.form.get("crn")
        term = request.form.get("term")
        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, SBCC.Class) \
                    and c.vcrn == crn \
                    and c.term == term:
                return monitor

        class_instance = SBCC.Class(crn, term)
        class_monitor = ClassMonitor(SBCC.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        base_url = "https://banner.sbcc.edu/PROD/pw_pub_sched"
        vsub = re.compile("(dept=)([A-Z]+)")
        vcrse = re.compile("(course=)(\d+)")
        availability = r"<td class=\"default3\">(-?\d*)</td>"

        def __init__(self, crn, term):
            super().__init__()
            self.url = SBCC.Class.base_url + ".p_course_popup?vterm={}&vcrn={}".format(term, crn)
            html = urlopen(self.url).read().decode()
            self.vcrn = crn
            self.vterm = term
            self.vsub = SBCC.Class.vsub.search(html).group(2)
            self.vcrse = SBCC.Class.vcrse.search(html).group(2)
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
            html = urlopen(self.url).read().decode()
            a = re.findall(SBCC.Class.availability, html)
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
