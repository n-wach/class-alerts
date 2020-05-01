import json
import re

from bs4 import BeautifulSoup

from tor import urlget

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College, template_environment, ClassUpdateException


class CalpolySLO(College):
    short_name = "Cal Poly SLO"
    name = "Cal Poly - San Luis Obispo"
    icon = "images/calpoly.png"

    first_look = urlget("https://pass.calpoly.edu/main.html")

    cookies = {"PS_DEVICEFEATURES": "width:1920 height:1080 pixelratio:1 touch:0 geolocation:1 websockets:1 webworkers:1 datepicker:1 dtpicker:1 timepicker:1 dnd:1 sessionstorage:1 localstorage:1 history:1 canvas:1 svg:1 postmessage:1 hc:0 maf:0",
               "CP-PASS-WhatsNew-20180130": "true",
               "JSESSIONID": first_look.history[1].cookies.get("JSESSIONID")}

    request = urlget("https://pass.calpoly.edu/getCourseSelectors.json", cookies=cookies)

    course_selectors = json.loads(request.text)
    departments = course_selectors["departments"]

    subjects = []
    for dept in departments:
        subjects.append((str(dept["id"]), "{} - {}".format(dept["name"], dept["description"])))

    add_template_params = {"subjects": subjects}

    add_template = template_environment.get_template("calpoly_slo/CalpolySLO.html")

    PATTERN_CATALOG_NUMBER = re.compile(r"\d+")
    PATTERN_CLASS_NUMBER = re.compile(r"\d+")

    @staticmethod
    def verify_add_request(form):
        subject = form.get("subject")
        catalog_number = form.get("catalog_number")
        class_number = form.get("class_number")
        if subject is None:
            return errors("Subject is missing", "class_add")
        if catalog_number is None:
            return errors("Catalog Number is missing", "class_add")
        if class_number is None:
            return errors("Class Number is missing", "class_add")

        if subject not in (subject[0] for subject in CalpolySLO.subjects):
            return errors("Invalid subject", "class_add")
        if not CalpolySLO.PATTERN_CATALOG_NUMBER.match(catalog_number):
            return errors("Invalid Catalog Number", "class_add")
        if not CalpolySLO.PATTERN_CLASS_NUMBER.match(class_number):
            return errors("Invalid Class Number", "class_add")

        return True

    @staticmethod
    def monitor_from_add_request(form):
        subject = form.get("subject")
        catalog_number = form.get("catalog_number")
        class_number = form.get("class_number")

        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, CalpolySLO.Class) \
                    and c.subject == subject \
                    and c.catalog_number == catalog_number \
                    and c.class_number == class_number:
                return monitor

        class_instance = CalpolySLO.Class(subject, catalog_number, class_number)
        class_monitor = ClassMonitor(CalpolySLO.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        def __init__(self, subject, catalog_number, class_number):
            super().__init__()
            self.subject = subject
            self.catalog_number = catalog_number
            self.class_number = class_number

            cookie_fetcher = urlget("https://pass.calpoly.edu/main.html")

            cookies = {
                "PS_DEVICEFEATURES": "width:1920 height:1080 pixelratio:1 touch:0 geolocation:1 websockets:1 webworkers:1 datepicker:1 dtpicker:1 timepicker:1 dnd:1 sessionstorage:1 localstorage:1 history:1 canvas:1 svg:1 postmessage:1 hc:0 maf:0",
                "CP-PASS-WhatsNew-20180130": "true",
                "JSESSIONID": cookie_fetcher.history[1].cookies.get("JSESSIONID")}

            params = (("deptId", self.subject),)

            raw = urlget("https://pass.calpoly.edu/searchByDept.json", cookies=cookies, params=params).text

            dept_search = json.loads(raw)
            for course in dept_search:
                if course["catalogNumber"] == self.catalog_number:
                    self.course_id = course["id"]
                    break
            else:
                raise ClassUpdateException("Catalog Number not found")

            self.display_name = "Calpoly SLO Unnamed"
            self.status_message = "Calpoly SLO Status"
            self.info_url = "https://pass.calpoly.edu/main.html"
            self.action_url = "https://pass.calpoly.edu/main.html"

            self.update_status()

        def update_status(self):

            cookie_fetcher = urlget("https://pass.calpoly.edu/main.html")

            cookies = {
                "PS_DEVICEFEATURES": "width:1920 height:1080 pixelratio:1 touch:0 geolocation:1 websockets:1 webworkers:1 datepicker:1 dtpicker:1 timepicker:1 dnd:1 sessionstorage:1 localstorage:1 history:1 canvas:1 svg:1 postmessage:1 hc:0 maf:0",
                "CP-PASS-WhatsNew-20180130": "true",
                "JSESSIONID": cookie_fetcher.history[1].cookies.get("JSESSIONID")}

            params = (("courseId", self.course_id),)
            add_response = urlget("https://pass.calpoly.edu/addCourse.json", cookies=cookies, params=params)

            results = BeautifulSoup(urlget("https://pass.calpoly.edu/next.do", cookies=cookies).text, "html.parser")

            sections = results.find_all("td", class_="sectionNumber")
            for section in sections:
                data = section.parent.findChildren("td")
                data = data[data.index(section):]
                print(data[2].string)
                if data[2].string == self.class_number:
                    open_seats = int(data[4].string)
                    open_reserved_seats = int(data[5].string)
                    waiting = int(data[7].string)
                    section_header = results.find("div", class_="select-course")
                    name = list(section_header.h3.stripped_strings)[0].split("\u2014")[0].strip()
                    print(name)
                    self.display_name = "{} - {} {} ({})".format(name, data[1].string, data[0].string, data[2].string)
                    self.status_message = "Open: {} | Open Reserved: {} | Waiting: {}".format(open_seats, open_reserved_seats, waiting)
                    self.has_availability = open_seats > 0 and waiting == 0
                    return self.has_availability

            raise ClassUpdateException("Class number not found in results page")

        def __str__(self):
            return "<CalpolySLO {}>".format(self.display_name)
