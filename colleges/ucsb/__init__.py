import re
import os

from tor import urlget
from bs4 import BeautifulSoup

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College, ClassUpdateException, template_environment


class UCSB(College):
    short_name = "UCSB"
    name = "University of California Santa Barbara"
    icon = "images/ucsb.png"

    API_KEY = os.environ.get("UCSB_API_KEY", "not-set")
    API_URL_BASE = "https://api.ucsb.edu/academics/curriculums/v1/classsection/"

    API_HEADERS = {
        'accept': 'application/json',
        'ucsb-api-version': '1.0',
        'ucsb-api-key': API_KEY,
    }

    renewal_period = "quarter"
    renewal_cost = 3

    landing_page_request = urlget("https://my.sa.ucsb.edu/public/curriculum/coursesearch.aspx")

    landing_page = BeautifulSoup(landing_page_request.text, "html.parser")
    quarter_options = landing_page.find(id="ctl00_pageContent1_quarterList").findChildren()

    quarters = [(quarter_option["value"], quarter_option.string.strip().capitalize()) for quarter_option in quarter_options]

    add_template_params = {"quarters": quarters}

    add_template = template_environment.get_template("ucsb/UCSB.html")

    PATTERN_CODE = re.compile(r"[0-9]{1,5}(?:\/[A-Z])?")

    @staticmethod
    def verify_add_request(form):
        quarter = form.get("quarter")
        code = form.get("code")
        if quarter is None:
            return errors("Quarter is missing", "class_add")
        if code is None:
            return errors("Code is missing", "class_add")

        if quarter not in (quarter[0] for quarter in UCSB.quarters):
            return errors("Invalid quarter", "class_add")
        if not UCSB.PATTERN_CODE.match(code):
            return errors("Invalid code", "class_add")

        return True

    @staticmethod
    def monitor_from_add_request(form):
        quarter = form.get("quarter")
        code = form.get("code")

        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, UCSB.Class) \
                    and c.quarter == quarter \
                    and c.code == code:
                return monitor

        class_instance = UCSB.Class(quarter, code)
        class_monitor = ClassMonitor(UCSB.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        def __init__(self, quarter, code):
            super().__init__()
            self.quarter = quarter
            self.code = code
            self.total_normal_seats = 0
            self.taken_normal_seats = 0

            self.display_name = "UCSB Unnamed"
            self.status_message = "UCSB Status"
            self.info_url = "https://my.sa.ucsb.edu/public/curriculum/coursesearch.aspx"
            self.action_url = "https://my.sa.ucsb.edu/gold/login.aspx"

            self.update_status()

        def update_status(self):

            response = urlget(UCSB.API_URL_BASE + "{}/{}".format(self.quarter, self.code), headers=UCSB.API_HEADERS)

            if response.status_code != 200:
                raise ClassUpdateException("UCSB API call failed")

            class_info = response.json()

            self.display_name = class_info["title"]
            total = 0
            taken = 0
            for section in class_info["classSections"]:
                total += section["maxEnroll"]
                taken += section["enrolledTotal"]

            self.taken_normal_seats = taken
            self.total_normal_seats = total

            self.status_message = "Seats Taken: {} / {}".format(taken, total)

            self.has_availability = self.taken_normal_seats < self.total_normal_seats

            return self.has_availability

        def __str__(self):
            return "<UCSB {}>".format(self.display_name)
