import re

from tor import urlget, urlpost
from bs4 import BeautifulSoup

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College, ClassUpdateException, template_environment


class UCLA(College):
    short_name = "UCLA"
    name = "University of California Los Angeles"
    icon = "images/ucla.png"

    renewal_period = "quarter"
    renewal_cost = 3

    search_page = BeautifulSoup(urlget("https://sa.ucla.edu/ro/public/soc").text, "html.parser")

    term_select = search_page.find("select", id="optSelectTerm").find_all("option")

    terms = []
    for term in term_select:
        terms.append((term["value"], term["data-yeartext"]))

    add_template_params = {"terms": terms}

    add_template = template_environment.get_template("ucla/UCLA.html")

    PATTERN_CLASS_ID = re.compile(r"\d{9}")

    @staticmethod
    def verify_add_request(form):
        term = form.get("term")
        class_id = form.get("class_id")
        if term is None:
            return errors("Term is missing", "class_add")
        if class_id is None:
            return errors("Section is missing", "class_add")

        if term not in (term[0] for term in UCLA.terms):
            return errors("Invalid term", "class_add")
        if not UCLA.PATTERN_CLASS_ID.match(class_id):
            return errors("Invalid class id", "class_add")

        return True

    @staticmethod
    def monitor_from_add_request(form):
        term = form.get("term")
        class_id = form.get("class_id")

        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, UCLA.Class) \
                    and c.term == term \
                    and c.class_id == class_id:
                return monitor

        class_instance = UCLA.Class(term, class_id)
        class_monitor = ClassMonitor(UCLA.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        def __init__(self, term, class_id):
            super().__init__()
            self.term = term
            self.class_id = class_id

            self.total_normal_seats = 0
            self.taken_normal_seats = 0
            self.total_waitlist_seats = 0
            self.waitlist_seats_avail = 0

            self.display_name = "UCLA Unnamed"
            self.status_message = "UCLA Status"

            search_params = {
                "t": self.term,
                "sBy": "classidnumber",
                "id": self.class_id
            }

            search_results = urlget("https://sa.ucla.edu/ro/Public/SOC/Results", params=search_params)

            search_page = BeautifulSoup(search_results.text, "html.parser")

            possible_sections = search_page.find_all("div", class_="sectionColumn")

            for section in possible_sections:
                if section.div:
                    class_detail_url = section.div.p.a["href"]
                    if self.class_id in class_detail_url:
                        self.info_url = "https://sa.ucla.edu" + class_detail_url
                        break
            else:
                raise ClassUpdateException("Class section not found in search results")

            self.action_url = "http://my.ucla.edu/directLink.aspx?featureID=203"

            self.update_status()

        def update_status(self):
            response = urlpost(self.info_url, tor=True)
            info_page = BeautifulSoup(response.text, "html.parser")

            raw_name = list(info_page.find("div", id="subject_class").p.stripped_strings)[-1]
            class_name = raw_name.strip()
            raw_section = list(info_page.find("div", id="class_id_textbook").p.stripped_strings)[0]
            section = raw_section.split(":")[-1].strip().upper()
            self.display_name = "{} - {} ({})".format(" ".join(class_name.replace("\t", " ").split()), section, self.class_id)

            enrollment_info = info_page.find("div", id="enrl_mtng_info").find_all("tr", class_="enrl_mtng_info")
            status, waitlist_status, days, time, location, units, instructor = enrollment_info[-1].findChildren(recursive=False)
            self.status_message = status.string + " | " + waitlist_status.string

            self.has_availability = "Open" in self.status_message
            return self.has_availability

        def __str__(self):
            return "<UCLA {}>".format(self.display_name)
