import re

from tor import urlget, urlpost
from bs4 import BeautifulSoup

from jinja2 import Template

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College, ClassUpdateException, template_environment


class UCSB(College):
    short_name = "UCSB"
    name = "University of California Santa Barbara"
    icon = "images/ucsb.png"

    landing_page_request = urlget("https://my.sa.ucsb.edu/public/curriculum/coursesearch.aspx")

    landing_page = BeautifulSoup(landing_page_request.text, "html.parser")

    subject_options = landing_page.find(id="ctl00_pageContent_courseList").findChildren()
    quarter_options = landing_page.find(id="ctl00_pageContent_quarterList").findChildren()

    subjects = [(subject_option["value"], subject_option.string.split("-")[0].strip()) for subject_option in subject_options]
    quarters = [(quarter_option["value"], quarter_option.string.strip().capitalize()) for quarter_option in quarter_options]

    add_template_params = {"subjects": subjects, "quarters": quarters}

    view_state = landing_page.find(id="__VIEWSTATE")["value"]
    view_state_generator = landing_page.find(id="__VIEWSTATEGENERATOR")["value"]
    event_validation = landing_page.find(id="__EVENTVALIDATION")["value"]

    request_cookies = landing_page_request.cookies.get_dict()

    add_template = template_environment.get_template("ucsb/UCSB.html")

    PATTERN_CODE = re.compile(r"[0-9]{1,5}(?:\/[A-Z])?")

    @staticmethod
    def verify_add_request(form):
        subject = form.get("subject")
        quarter = form.get("quarter")
        code = form.get("code")
        if subject is None:
            return errors("Subject is missing", "class_add")
        if quarter is None:
            return errors("Quarter is missing", "class_add")
        if code is None:
            return errors("Code is missing", "class_add")

        if subject not in (subject[0] for subject in UCSB.subjects):
            return errors("Invalid subject", "class_add")
        if quarter not in (quarter[0] for quarter in UCSB.quarters):
            return errors("Invalid quarter", "class_add")
        if not UCSB.PATTERN_CODE.match(code):
            return errors("Invalid code", "class_add")

        return True

    @staticmethod
    def monitor_from_add_request(form):
        subject = form.get("subject")
        quarter = form.get("quarter")
        code = form.get("code")

        if "/" in code:
            number, section = code.split("/")
            code = number.zfill(5) + "/" + section
        else:
            code = code.zfill(5)

        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, UCSB.Class) \
                    and c.subject == subject \
                    and c.quarter == quarter \
                    and c.code == code:
                return monitor

        class_instance = UCSB.Class(subject, quarter, code)
        class_monitor = ClassMonitor(UCSB.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        def __init__(self, subject, quarter, code):
            super().__init__()
            self.subject = subject
            self.quarter = quarter
            self.code = code
            self.total_normal_seats = 0
            self.taken_normal_seats = 0
            self.total_waitlist_seats = 0
            self.waitlist_seats_avail = 0

            self.display_name = "UCSB Unnamed"
            self.status_message = "UCSB Status"
            self.info_url = "https://my.sa.ucsb.edu/public/curriculum/coursesearch.aspx"

            self.update_status()

        def update_status(self):
            data = {
                '__VIEWSTATE': UCSB.view_state,
                '__VIEWSTATEGENERATOR': UCSB.view_state_generator,
                '__EVENTVALIDATION': UCSB.event_validation,
                'ctl00$pageContent$courseList': self.subject,
                'ctl00$pageContent$quarterList': self.quarter,
                'ctl00$pageContent$dropDownCourseLevels': 'All',
                'ctl00$pageContent$searchButton.x': '56',
                'ctl00$pageContent$searchButton.y': '7'
            }

            request = urlpost('https://my.sa.ucsb.edu/public/curriculum/coursesearch.aspx', cookies=UCSB.request_cookies, data=data)

            results_page = BeautifulSoup(request.text, "html.parser")

            rows = results_page.find_all("tr", class_="CourseInfoRow")

            last_title = "Untitled Class"
            for row in rows:
                _, course_id, title, status, code, instructor, days, time, location, enrolled, _ = row.findChildren("td", recursive=False)
                if title.span.string:
                    last_title = title.span.string.strip()
                if code.a.string and code.a.string.strip() == self.code:
                    self.display_name = "{}: {} ({})".format(" ".join(list(course_id.stripped_strings)[0].split()), last_title, self.code)
                    status_string = list(status.stripped_strings)
                    if len(status_string) == 0:
                        self.status_message = "{}".format(enrolled.string)
                    else:
                        self.status_message = "{}: {}".format(list(status.stripped_strings)[0], enrolled.string)
                    self.total_normal_seats = int(enrolled.string.split("/")[1].strip())
                    self.taken_normal_seats = int(enrolled.string.split("/")[0].strip())
                    break
            else:
                raise ClassUpdateException("Failed to find code")

            self.has_availability = self.taken_normal_seats < self.total_normal_seats

            return self.has_availability

        def __str__(self):
            return "<UCSB {}>".format(self.display_name)
