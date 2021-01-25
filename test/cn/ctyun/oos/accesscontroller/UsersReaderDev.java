package cn.ctyun.oos.accesscontroller;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class UsersReaderDev {

    public static List<User> getUsers() throws FileNotFoundException, IOException {
        List<User> users = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader("users.txt"))) {
            String line = null;
            while ((line = r.readLine()) != null) {
                User user = new User();
                String[] strs = line.split(",");
                user.userName = strs[0];
                user.accessKey = strs[1];
                user.secretKey = strs[2];
                users.add(user);
            }
        }
        return users;
    }

    public static class User {
        public String userName;
        public String accessKey;
        public String secretKey;
    }

}
