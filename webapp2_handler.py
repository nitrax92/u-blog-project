import webapp2
import jinja2
import logging
import os



template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

""" Webapp2 combined with Jinja2 handling. """
class GeneralHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, message='', **kw):
        if self.user:
            kw['user'] = self.user

        if message:
            kw['message'] = message

        self.write(self.render_str(template, **kw))
