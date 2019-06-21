//
//  ViewController.swift
//  KeychainDemo
//
//  Created by Nicolás Miari on 2019/06/21.
//  Copyright © 2019 Nicolás Miari. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.

        let password = "123456"

        LocalCredentialStore.storePassword(password, protectWithPasscode: false, completion: {
            LocalCredentialStore.loadPassword { (loadedPassword) in
                guard let loadedPassword = loadedPassword else {
                    fatalError("Password not found!")
                }
                print("Loaded: \(loadedPassword)")
            }
        }, failure: {(error) in
            print(error.localizedDescription)
        })
    }
}

