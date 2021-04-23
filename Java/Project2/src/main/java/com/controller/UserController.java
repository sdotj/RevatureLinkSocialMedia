package com.controller;

import com.model.CustomResponseMessage;
import com.model.User;
import com.service.UserService;
import org.apache.commons.mail.DefaultAuthenticator;
import org.apache.commons.mail.Email;
import org.apache.commons.mail.EmailException;
import org.apache.commons.mail.SimpleEmail;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.SecureRandom;
import java.util.List;

@RestController
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RequestMapping("/users")
public class UserController {

    private UserService userService;
    final static Logger loggy = Logger.getLogger(UserController.class);
    static {
        loggy.setLevel(Level.ALL);
        //loggy.setLevel(Level.ERROR);
    }

    @GetMapping(value="getAllUsers")
    public List<User> getAllUsers(){
        loggy.info("All Users was retrieved from serviceLayer");
        return userService.selectAllUsers();
    }

    @GetMapping(value = "/getUserById/{userId}")
    public User getUserById(@PathVariable("userId") int userId){
        loggy.info("A user with id: "+userId+" was retrieved.");
        return userService.selectById(userId);
    }

    @PostMapping(value = "/getByUserAndPass")
    public User getUserByUserAndPass(@RequestBody User user){
        loggy.info("An attempt to retrieve a user with username: "+user.getUsername()+" with a password.");
        return userService.selectByUsernameAndPassword(user.getUsername(),user.getPassword());
    }

    @PostMapping(value = "/getByUsername")
    public User getUserByUsername(@RequestBody User user) {
        loggy.info("An attempt to retrieve a user with username: "+user.getUsername()+".");
        return userService.selectByUsername(user.getUsername());
    }

    @PostMapping(value = "/checkOldPassword")
    public CustomResponseMessage checkOldPassword(@RequestBody User user) {

        if(userService.checkOldPassword(user.getUsername(),user.getPassword())) {
            loggy.info("The valid old password of a user with username: "+user.getUsername()+" was correct.");
            return new CustomResponseMessage("yes");
        }else{
            loggy.info("The old password of a user with username: "+user.getUsername()+" is not correct.");
            return null;
        }
    }

    @PostMapping(value = "/insertNewUser")
    public CustomResponseMessage insertNewUser(@RequestBody User user){
        User alreadyExists = getUserByUsername(user);
        if(alreadyExists == null) {
            userService.insert(user);
            loggy.info("The successful creation of a user with username: "+user.getUsername()+".");
            return new CustomResponseMessage("User was created");
        }
        else {
            loggy.info("The failed creation of a user with username: "+user.getUsername()+".");
            return new CustomResponseMessage("Username already taken");
        }
    }
    @PutMapping(value = "/updateUser")
    public CustomResponseMessage updateUser(HttpSession session,@RequestBody User user){
        if((User)session.getAttribute("loggedInUser")!=null){
            User current=((User)session.getAttribute("loggedInUser"));
            if(!current.getPassword().equals(user.getPassword())){
                userService.updateWithPassword(user);
                loggy.info("The successful update(with password) of a user with username: "+user.getUsername()+".");
            }
            else {
                loggy.info("The successful update of a user with username: "+user.getUsername()+".");
                userService.update(user);
            }
            int id = current.getUserId();
            User updatedVersion=getUserById(id);
            session.setAttribute("loggedInUser",updatedVersion);
            return new CustomResponseMessage("User was updated");
        }
        loggy.info("The failed update of a user with username: "+user.getUsername()+".");
        return new CustomResponseMessage("User was not updated");

    }
    @PostMapping(value = "/deleteUser")
    public CustomResponseMessage deleteUser(@RequestBody User user){
        userService.delete(user);
        loggy.info("The deletion of a user with username: "+user.getUsername()+".");
        return new CustomResponseMessage("User was deleted");
    }

    @GetMapping(value = "/getLoggedInUser")
    public User getLoggedInUser(HttpSession session){
        //try to get the most updated version of the user
        if((User)session.getAttribute("loggedInUser")!=null){
            int id = ((User)session.getAttribute("loggedInUser")).getUserId();
            User updatedVersion=userService.selectById(id);
            session.setAttribute("loggedInUser",updatedVersion);
            loggy.info("The successful retrieval of the loggedInUser");
            return (User) session.getAttribute("loggedInUser");
        }
        else{
            loggy.info("The failed retrieval of the loggedInUser");
            return null;
        }
    }


    @PostMapping(value = "/login")
    @ResponseBody
    public User login(HttpSession session, @RequestBody User currentUser){
        User retrievedUser = userService.selectByUsernameAndPassword(currentUser.getUsername(),currentUser.getPassword());
        session.setAttribute("loggedInUser",retrievedUser);
        loggy.info("The successful login of the user:"+currentUser.getUsername());
        return retrievedUser;
    }
    @GetMapping(value = "logout")
    public CustomResponseMessage logout(HttpServletRequest myReq){
        HttpSession userSession = myReq.getSession();
        loggy.info("The successful logout of the session:"+userSession);
        userSession.invalidate();
        return new CustomResponseMessage("Logged out");
    }

    @PostMapping(value = "/resetPassword")
    public CustomResponseMessage sendEmail(@RequestBody String userName){
        User tempUser = new User();
        tempUser.setUsername(userName);
        User user = getUserByUsername(tempUser);//retrieving the user in the database with the username
        if(user ==null){
            loggy.warn("The failed sending of an email due to the user not existing");
            return new CustomResponseMessage("Sending Email Failed");
        }
        String newPassword = generateTempPassword(20);//creating new random password
        user.setPassword(newPassword);
        userService.updateWithPassword(user);//updating the user in the database with temp password
        try {
            Email email = new SimpleEmail();
            email.setHostName("smtp.googlemail.com");
            email.setSmtpPort(465);
            email.setAuthenticator(
                    new DefaultAuthenticator(System.getenv("EMAILING_ADDRESS")//
                            , System.getenv("EMAILING_PASSWORD")));//
            email.setSSLOnConnect(true);
            email.setFrom(System.getenv("EMAILING_ADDRESS"));
            email.setSubject("Reset Password for Toph Link");
            email.setMsg("Your new password: \"" + newPassword+"\"");
            email.addTo(user.getEmailAddress());
            email.send(); // will throw email-exception if something is wrong
        } catch (EmailException e) {
            e.printStackTrace();
            loggy.warn("The failed sending of an email");
            return new CustomResponseMessage("Sending Email Failed");
        }
        loggy.info("Email sent to:"+user.getEmailAddress());
        return new CustomResponseMessage("Sending Email Success");
    }

    public String generateTempPassword(int length){
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();

        // each iteration of the loop randomly chooses a character from the given
        // ASCII range and appends it to the `StringBuilder` instance

        for (int i = 0; i < length; i++)
        {
            int randomIndex = random.nextInt(chars.length());
            sb.append(chars.charAt(randomIndex));
        }

        return sb.toString();
    }


    public UserController() {
    }


    public UserController(UserService userService) {
        this.userService = userService;
    }


    public UserService getUserService() {
        return userService;
    }

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }
}
