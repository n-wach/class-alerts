from flask import session, url_for
from jinja2 import Environment, ChoiceLoader, FileSystemLoader, Template

loader = ChoiceLoader([FileSystemLoader("colleges/"),
                       FileSystemLoader("templates/")])
template_environment = Environment(loader=loader)
template_environment.globals.update(session=session)
template_environment.globals.update(url_for=url_for)


class ClassUpdateException(RuntimeError):
    pass


class College:
    short_name = "GC"
    name = "Generic College"
    icon = "dog.png"
    renewal_period = "quarter"
    renewal_cost = 3

    add_template_params = {}
    add_template = Template("<p>Generic College Add Template</p>")

    @staticmethod
    def verify_add_request(form):
        raise NotImplementedError

    @staticmethod
    def monitor_from_add_request(form):
        raise NotImplementedError

    class Class:
        def __init__(self):
            self.has_availability = False
            self.display_name = "Generic Class"
            self.status_message = "Generic Status"
            self.info_url = "classalerts.org"
            self.action_url = "classalerts.org"

        def update_status(self):
            raise NotImplementedError

        def __str__(self):
            return "<{} {}>".format(__name__, self.display_name)
