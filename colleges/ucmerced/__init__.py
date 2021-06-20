import re

from bs4 import BeautifulSoup

from tor import urlget

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College, template_environment


class UCMerced(College):
    short_name = "UC Merced"
    name = "University of California Merced"
    icon = "images/ucmerced.png"

    renewal_period = "quarter"
    renewal_cost = 5

    search_req = urlget("https://mystudentrecord.ucmerced.edu/pls/PROD/xhwschedule.p_selectsubject")

    search_page = BeautifulSoup(search_req.text, "html.parser")

    term_input = search_page.find_all("input", attrs={"type": "radio", "name": "validterm"})

    terms = []
    for entry in term_input:
        value = entry["value"]
        if "-" in value:
            # This skips individual summer sections
            continue
        term_name = list(entry.next_siblings)[1].string
        terms.append((value, term_name))

    add_template_params = {"terms": terms}

    add_template = template_environment.get_template("ucmerced/UCMerced.html")

    PATTERN_CRN = re.compile(r"[0-9]{5}")
    PATTERN_CRS = re.compile(r"[0-9]{3}[A-Z]*")

    @staticmethod
    def verify_add_request(form):
        term = form.get("term")
        crn = form.get("crn")
        sub = form.get("sub")
        crs = form.get("crs")
        if term is None:
            return errors("Term is missing", "class_add")
        if crn is None:
            return errors("CRN is missing", "class_add")
        if sub is None:
            return errors("Subject is missing", "class_add")
        if crs is None:
            return errors("Course Number is missing", "class_add")
        if term not in (term[0] for term in UCMerced.terms):
            return errors("Invalid term", "class_add")
        if not UCMerced.PATTERN_CRN.match(crn):
            return errors("Invalid CRN", "class_add")
        if not UCMerced.PATTERN_CRS.match(crs):
            return errors("Invalid CRS", "class_add")
        return True

    @staticmethod
    def monitor_from_add_request(form):
        crn = form.get("crn")
        crs = form.get("crs").upper()
        term = form.get("term")
        sub = form.get("sub")
        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, UCMerced.Class) \
                    and c.vcrn == crn \
                    and c.vcrs == crs \
                    and c.vterm == term \
                    and c.vsub == sub:
                return monitor

        class_instance = UCMerced.Class(crn, term, sub, crs)
        class_monitor = ClassMonitor(UCMerced.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        base_url = "https://mystudentrecord.ucmerced.edu/pls/PROD/xhwschedule.P_ViewCrnDetail?"
        PATTERN_AVAIL = re.compile(r"<td class=\"default3\">(-?\d*)</td>")

        def __init__(self, crn, term, sub, crs):
            super().__init__()
            self.url = UCMerced.Class.base_url + "subjcode={}&crsenumb={}&validterm={}&crn={}".format(sub, crs, term, crn)
            html = urlget(self.url)
            page = BeautifulSoup(html.text, 'html.parser')
            self.vcrn = crn
            self.vterm = term
            self.vsub = sub
            self.vcrs = crs
            self.capacity = 0
            self.actual = 0
            self.remaining = 0

            title = list(page.find(text="Title:").parent.next_siblings)[1].string
            self.display_name = "{} (CRN: {})".format(title, self.vcrn)
            self.status_message = "UCMerced Status"
            self.info_url = self.url
            self.action_url = "https://catcourses.ucmerced.edu/"
            self.update_status()

        def update_status(self):
            html = urlget(self.url)
            page = BeautifulSoup(html.text, 'html.parser')
            seats = list(page.find(text="Seats").parent.parent.next_siblings)
            self.capacity = int(seats[1].string)
            self.actual = int(seats[3].string)
            self.remaining = int(seats[5].string)
            self.status_message = "Seats Taken: {} / {} | Available: {}".format(
                self.actual,
                self.capacity,
                self.remaining)

            self.has_availability = self.remaining > 0
            return self.has_availability

        def __str__(self):
            return "<UCMerced {}>".format(self.display_name)
