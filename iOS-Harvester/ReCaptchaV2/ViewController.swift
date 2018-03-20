//
//  ViewController.swift
//  ReCaptchaV2
//
//  Created by Cosm00 on 3/19/18.
//  Copyright © 2018 Cosm00. All rights reserved.
//

import UIKit
import WebKit

class ViewController: UIViewController, UITextFieldDelegate{

    @IBOutlet weak var ScrollView: UIScrollView!
    @IBOutlet weak var webView: WKWebView!
    @IBOutlet weak var txtSitekey: UITextField!
    @IBOutlet weak var txtDomain: UITextField!
    @IBOutlet weak var txtServerIP: UITextField!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        txtSitekey.text = "6LeoeSkTAAAAAA9rkZs5oS82l69OEYjKRZAiKdaF"
        txtDomain.text = "http://checkout.shopify.com"
        txtServerIP.text = ""
        self.txtSitekey.delegate = self
        self.txtDomain.delegate = self
        self.txtServerIP.delegate = self
        // Do any additional setup after loading the view, typically from a nib.
    }
    @IBAction func btnReCaptcha(_ sender: Any) {
        startHarv(sitekey: txtSitekey.text!, serverip: txtServerIP.text!, domain: txtDomain.text!)
    }
    
    @IBAction func btnGoogle(_ sender: Any) {
        let url = URL(string: "https://accounts.google.com/signin/v2");
        let request = URLRequest(url: url!);
        webView.load(request);
    }
    
    func startHarv(sitekey: String, serverip: String, domain: String){
        let htmlstring = "<html><meta name=\'viewport\' content=\'width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no\' />\r\n<head>\r\n<style>\r\nform {\r\n  text-align: center;\r\n}\r\nbody {\r\n  text-align: center;\r\n\r\n  \r\n}\r\n\r\nh1 {\r\n  text-align: center;\r\n}\r\nh3 {\r\n  text-align: center;\r\n}\r\ndiv-captcha {\r\n      text-align: center;\r\n}\r\n    .g-recaptcha {\r\n        display: inline-block;\r\n    }\r\n</style>\r\n\r\n<meta name=\'referrer\' content=\'never\'> <script type='text/javascript' src='https://www.google.com/recaptcha/api.js'></script><script>function sub() {\n  post('http://serveriphere:5000/solve', {'g-recaptcha-response': document.getElementById('g-recaptcha-response').value})\n}\nfunction post(path, params, method) {\n    method = method || 'post';\n    var form = document.createElement('form');\n    form.setAttribute('method', method);\n    form.setAttribute('action', path);\n    for(var key in params) {\n        if(params.hasOwnProperty(key)) {\n            var hiddenField = document.createElement('input');\n            hiddenField.setAttribute('type', 'hidden');\n            hiddenField.setAttribute('name', key);\n            hiddenField.setAttribute('value', params[key]);\n            form.appendChild(hiddenField);\n        }\n    }\n    document.body.appendChild(form);\n    form.submit();\n}</script></head> <body bgcolor=\'#ffffff\'oncontextmenu=\'return false\'><div id=\'div-captcha\'><br><br><div style=\'opacity: 0.9\' class=\'g-recaptcha\' data-sitekey=\'sitekeyhere\' data-callback=\'sub\'></div></div><br>\r\n\r\n</body></html>";
        webView.loadHTMLString(htmlstring.replacingOccurrences(of: "sitekeyhere", with: sitekey).replacingOccurrences(of: "serveriphere", with:serverip), baseURL: URL(string: domain)!)
        
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        //stuff
        self.view.endEditing(true)
    }
    
    func textFieldDidBeginEditing(_ textField: UITextField) {
        ScrollView.setContentOffset(CGPoint(x: 0, y: 250), animated: true)
        
    }
    
    func textFieldDidEndEditing(_ textField: UITextField) {
        ScrollView.setContentOffset(CGPoint(x: 0, y: 0), animated: true)
        
    }
    
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        //stuff
        textField.resignFirstResponder()
        return (true)
        
    }


}

