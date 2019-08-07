import re

from bs4 import BeautifulSoup
from flask import json

from tor import urlget

from db import ClassMonitor, db
from decorators import errors
from colleges.generic import College, template_environment


class UCB(College):
    short_name = "UC Berkeley"
    name = "University of California Berkeley"
    icon = "images/ucb.png"

    courses_page = BeautifulSoup(urlget("http://guide.berkeley.edu/courses/").text, "html.parser")
    subject_links = courses_page.find(id="atozindex").findChildren("a")

    subject_name_re = re.compile(r"([A-z ]+)\s\(([A-Z]+)\)")

    subjects = []
    for link in subject_links:
        string = link.string
        match = subject_name_re.match(string)
        if match:
            subjects.append((match.group(2).lower(), string))

    terms = [("2019-fall", "Fall 2019")]

    add_template_params = {"terms": terms, "subjects": subjects}

    add_template = template_environment.get_template("ucb/Berkeley.html")

    PATTERN_COURSE = re.compile(r"[0-9A-Z]+")
    PATTERN_COURSE_NUMBER = re.compile(r"[0-9]+")
    PATTERN_SECTION_TYPE = re.compile(r"[A-Z]+")
    PATTERN_SECTION_NUMBER = re.compile(r"[0-9]+")

    @staticmethod
    def verify_add_request(form):
        term = form.get("term")
        subject = form.get("subject")
        course = form.get("course")
        course_number = form.get("course_number")
        section_type = form.get("section_type")
        section_number = form.get("section_number")
        if term is None:
            return errors("Term is missing", "class_add")
        if subject is None:
            return errors("Subject is missing", "class_add")
        if course is None:
            return errors("Course is missing", "class_add")
        if course_number is None:
            return errors("Course Number is missing", "class_add")
        if section_type is None:
            return errors("Section Type is missing", "class_add")
        if section_number is None:
            return errors("Section Number is missing", "class_add")

        if term not in (term[0] for term in UCB.terms):
            return errors("Invalid term", "class_add")
        if subject not in (subject[0] for subject in UCB.subjects):
            return errors("Invalid subject", "class_add")
        if not UCB.PATTERN_COURSE.match(course):
            return errors("Invalid course", "class_add")
        if not UCB.PATTERN_COURSE_NUMBER.match(course_number):
            return errors("Invalid course number", "class_add")
        if not UCB.PATTERN_SECTION_NUMBER.match(section_number):
            return errors("Invalid section number", "class_add")
        if not UCB.PATTERN_SECTION_TYPE.match(section_type):
            return errors("Invalid section type", "class_add")

        return True

    @staticmethod
    def monitor_from_add_request(form):
        term = form.get("term")
        subject = form.get("subject")
        course = form.get("course")
        course_number = form.get("course_number")
        section_type = form.get("section_type")
        section_number = form.get("section_number")

        for monitor in ClassMonitor.query.all():
            c = monitor.class_instance
            if isinstance(c, UCB.Class) \
                    and c.term == term \
                    and c.subject == subject \
                    and c.course == course \
                    and c.course_number == course_number \
                    and c.section_type == section_type \
                    and c.section_number == section_number:
                return monitor

        class_instance = UCB.Class(term, subject, course, course_number, section_type, section_number)
        class_monitor = ClassMonitor(UCB.short_name, class_instance)
        db.session.add(class_monitor)
        return class_monitor

    class Class(College.Class):
        def __init__(self, term, subject, course, course_number, section_type, section_number):
            super().__init__()
            self.term = term
            self.subject = subject
            self.course = course
            self.course_number = course_number
            self.section_type = section_type
            self.section_number = section_number

            self.waitlisted_count = 0
            self.max_waitlist = 0
            self.open_reserved = 0
            self.reserved_count = 0
            self.enrolled_count = 0
            self.max_enrolled = 0

            self.display_name = "UCB Unnamed"
            self.status_message = "UCB Status"
            self.info_url = "https://classes.berkeley.edu/content/{}-{}-{}-{}-{}-{}".format(term,
                                                                                            subject,
                                                                                            course.lower(),
                                                                                            course_number.lower(),
                                                                                            section_type.lower(),
                                                                                            section_number.lower())
            self.action_url = "https://calcentral.berkeley.edu/"
            self.update_status()

        def update_status(self):
            request = urlget(self.info_url)
            class_info_page = BeautifulSoup(request.text, "html.parser")

            data = json.loads(class_info_page.find(class_="handlebarData")["data-json"])

            self.display_name = data["displayName"]

            self.waitlisted_count = data["enrollmentStatus"]["waitlistedCount"]
            self.max_waitlist = data["enrollmentStatus"]["maxWaitlist"]
            self.open_reserved = data["enrollmentStatus"]["openReserved"]
            self.reserved_count = data["enrollmentStatus"]["reservedCount"]
            self.enrolled_count = data["enrollmentStatus"]["enrolledCount"]
            self.max_enrolled = data["enrollmentStatus"]["maxEnroll"]

            status = data["enrollmentStatus"]["status"]["description"]

            if self.max_waitlist > 0:
                self.status_message = "{}: {} / {}".format(status, self.enrolled_count, self.max_enrolled)
            else:
                self.status_message = "{}: {} / {} | Waitlist: {} / {}".format(status,
                                                                               self.enrolled_count,
                                                                               self.max_enrolled,
                                                                               self.waitlisted_count,
                                                                               self.max_waitlist)

            if self.max_waitlist == 0:
                self.has_availability = self.enrolled_count < self.max_enrolled
            else:
                self.has_availability = self.waitlisted_count < self.max_waitlist

            return self.has_availability

        def __str__(self):
            return "<UCB {}>".format(self.display_name)
