import os

from paypal import PayPalConfig
from paypal import PayPalInterface

from DB import Payment
from decorators import requires_paid, requires_signin
from app import current_user, get_user_college, url_for, db, redirect, render_template, request


# SANBOX CREDS
pp_config_sandbox = PayPalConfig(API_USERNAME="sbccalerts-merchant_api1.gmail.com",
                                 API_PASSWORD=os.environ.get("PAYPAL_DEV_PASSWORD"),
                                 API_SIGNATURE=os.environ.get("PAYPAL_DEV_SIGNATURE"),
                                 API_ENVIRONMENT="SANDBOX")
pp_interface_sandbox = PayPalInterface(config=pp_config_sandbox)

# LIVE CREDS
pp_config_live = PayPalConfig(API_USERNAME="sbccalerts_api2.gmail.com",
                              API_PASSWORD=os.environ.get("PAYPAL_PROD_PASSWORD"),
                              API_SIGNATURE=os.environ.get("PAYPAL_PROD_SIGNATURE"),
                              API_ENVIRONMENT="PRODUCTION")
pp_interface_live = PayPalInterface(config=pp_config_live)

pp_interface = pp_interface_sandbox


def route(app):
    # thanks to https://github.com/jdiez17/flask-paypal/blob/master/app.py

    @app.route("/paypal/redirect")
    @requires_signin
    @requires_paid(paid=False)
    def paypal_redirect():
        cur_user = current_user()
        PAYPAL_UUID_PURCHASE = {
            'amt': get_user_college(current_user()).renewal_cost,
            'currencycode': 'USD',
            'returnurl': url_for('paypal_confirm', _external=True),
            'cancelurl': url_for('paypal_cancel', _external=True),
            'paymentaction': 'Sale',
        }
        setexp_response = pp_interface.set_express_checkout(**PAYPAL_UUID_PURCHASE)
        r_token = setexp_response['TOKEN']
        payment = Payment(r_token, cur_user)
        db.session.add(payment)
        db.session.commit()
        return redirect(pp_interface.generate_express_checkout_redirect_url(r_token))

    @app.route("/paypal/confirm")
    def paypal_confirm():
        getexp_response = pp_interface.get_express_checkout_details(token=request.args.get('token', ''))

        return render_template("payments/payment-info.html", resp=getexp_response)

    @app.route("/paypal/do/<string:token>")
    def paypal_do(token):
        getexp_response = pp_interface.get_express_checkout_details(token=token)
        kw = {
            'amt': getexp_response['AMT'],
            'paymentaction': 'Sale',
            'payerid': getexp_response['PAYERID'],
            'token': token,
            'currencycode': getexp_response['CURRENCYCODE']
        }
        pp_interface.do_express_checkout_payment(**kw)

        return redirect(url_for('paypal_status', token=kw['token']))

    @app.route("/paypal/status/<string:token>")
    def paypal_status(token):
        checkout_response = pp_interface.get_express_checkout_details(token=token)
        payment = Payment.query.filter_by(token=token).first()
        if payment is None:
            return "Failed. Token: " + str(token)
        payment.set_email(checkout_response['EMAIL'])

        if checkout_response['CHECKOUTSTATUS'] == 'PaymentActionCompleted':
            payment.process()
            payment.set_status(1)

        return render_template("payments/payment-status.html", resp=checkout_response, payment=payment)

    @app.route("/paypal/cancel")
    def paypal_cancel():
        payment = Payment.query.filter_by(token=request.args.get('token', '')).first()
        if payment is not None:
            payment.cancel()
        return redirect(url_for('landing_page'))
