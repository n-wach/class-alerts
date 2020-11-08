import re

from tor import urlget, urlpost
from bs4 import BeautifulSoup

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College, ClassUpdateException, template_environment


class UCSD(College):
    short_name = "UCSD"
    name = "University of California San Diego"
    icon = "images/ucsd.png"

    renewal_period = "quarter"
    renewal_cost = 3

    search_page = BeautifulSoup(urlget("https://act.ucsd.edu/scheduleOfClasses/scheduleOfClassesStudent.htm").text, "html.parser")

    term_select = search_page.find("select", id="selectedTerm").findChildren()

    terms = []
    for term in term_select:
        terms.append((term["value"], term.string.strip()))

    add_template_params = {"terms": terms}

    add_template = template_environment.get_template("ucsd/UCSD.html")

    PATTERN_SECTION = re.compile(r"\d+")

    @staticmethod
    def verify_add_request(form):
        term = form.get("term")
        section = form.get("section")
        if term is None:
            return errors("Term is missing", "class_add")
        if section is None:
            return errors("Section is missing", "class_add")

        if term not in (term[0] for term in UCSD.terms):
            return errors("Invalid term", "class_add")
        if not UCSD.PATTERN_SECTION.match(section):
            return errors("Invalid section code", "class_add")

        return True

    @staticmethod
    def monitor_from_add_request(form):
        term = form.get("term")
        section = form.get("section")

        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, UCSD.Class) \
                    and c.term == term \
                    and c.section == section:
                return monitor

        class_instance = UCSD.Class(term, section)
        class_monitor = ClassMonitor(UCSD.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        def __init__(self, term, section):
            super().__init__()
            self.term = term
            self.section = section

            self.total_normal_seats = 0
            self.taken_normal_seats = 0
            self.total_waitlist_seats = 0
            self.waitlist_seats_avail = 0

            self.display_name = "UCSD Unnamed"
            self.status_message = "UCSD Status"
            self.info_url = "https://act.ucsd.edu/scheduleOfClasses/scheduleOfClassesStudent.htm"
            self.action_url = "https://a5.ucsd.edu/tritON/profile/SAML2/Redirect/SSO?execution=e2s1"

            self.update_status()

        def update_status(self):
            data = [
                ('selectedTerm', self.term),
                ('xsoc_term', ''),
                ('loggedIn', 'false'),
                ('tabNum', 'tabs-sec'),
                ('_selectedSubjects', '1'),
                ('schedOption1', 'true'),
                ('_schedOption1', 'on'),
                ('_schedOption11', 'on'),
                ('_schedOption12', 'on'),
                ('schedOption2', 'true'),
                ('_schedOption2', 'on'),
                ('_schedOption4', 'on'),
                ('_schedOption5', 'on'),
                ('_schedOption3', 'on'),
                ('_schedOption7', 'on'),
                ('_schedOption8', 'on'),
                ('_schedOption13', 'on'),
                ('_schedOption10', 'on'),
                ('_schedOption9', 'on'),
                ('schDay', 'M'),
                ('schDay', 'T'),
                ('schDay', 'W'),
                ('schDay', 'R'),
                ('schDay', 'F'),
                ('schDay', 'S'),
                ('_schDay', 'on'),
                ('_schDay', 'on'),
                ('_schDay', 'on'),
                ('_schDay', 'on'),
                ('_schDay', 'on'),
                ('_schDay', 'on'),
                ('schStartTime', '12:00'),
                ('schStartAmPm', '0'),
                ('schEndTime', '12:00'),
                ('schEndAmPm', '0'),
                ('_selectedDepartments', '1'),
                ('schedOption1Dept', 'true'),
                ('_schedOption1Dept', 'on'),
                ('_schedOption11Dept', 'on'),
                ('_schedOption12Dept', 'on'),
                ('schedOption2Dept', 'true'),
                ('_schedOption2Dept', 'on'),
                ('_schedOption4Dept', 'on'),
                ('_schedOption5Dept', 'on'),
                ('_schedOption3Dept', 'on'),
                ('_schedOption7Dept', 'on'),
                ('_schedOption8Dept', 'on'),
                ('_schedOption13Dept', 'on'),
                ('_schedOption10Dept', 'on'),
                ('_schedOption9Dept', 'on'),
                ('schDayDept', 'M'),
                ('schDayDept', 'T'),
                ('schDayDept', 'W'),
                ('schDayDept', 'R'),
                ('schDayDept', 'F'),
                ('schDayDept', 'S'),
                ('_schDayDept', 'on'),
                ('_schDayDept', 'on'),
                ('_schDayDept', 'on'),
                ('_schDayDept', 'on'),
                ('_schDayDept', 'on'),
                ('_schDayDept', 'on'),
                ('schStartTimeDept', '12:00'),
                ('schStartAmPmDept', '0'),
                ('schEndTimeDept', '12:00'),
                ('schEndAmPmDept', '0'),
                ('courses', ''),
                ('sections', self.section),
                ('instructorType', 'begin'),
                ('instructor', ''),
                ('titleType', 'contain'),
                ('title', ''),
                ('_hideFullSec', 'on'),
                ('_showPopup', 'on'),
            ]

            response = urlpost('https://act.ucsd.edu/scheduleOfClasses/scheduleOfClassesStudentResult.htm',
                               data=data)

            results_page = BeautifulSoup(response.text, "html.parser")
            sections = results_page.find_all("tr", class_="sectxt")
            for section in sections:
                data = section.findChildren("td")
                section_id = data[2].string.strip()
                if section_id == self.section:
                    header_data = results_page.find_all("td", class_="crsheader")
                    course_name = list(header_data[2].stripped_strings)[0]
                    meeting_type = data[3].string.strip()
                    section_name = data[4].string.strip()
                    self.display_name = "{} {} {} ({})".format(course_name, meeting_type, section_name, section_id)
                    available_seats = " ".join(data[10].stripped_strings)
                    if "FULL" in available_seats:
                        self.has_availability = False
                        self.status_message = available_seats
                    else:
                        self.has_availability = True
                        available = int(available_seats.strip())
                        total = int(data[11].string.strip())
                        self.status_message = "Open: {} / {}".format(total - available, available)
                    return self.has_availability

            raise ClassUpdateException("Failed to find matching section TR")

        def __str__(self):
            return "<UCSD {}>".format(self.display_name)
