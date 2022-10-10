package pers.melii.cill.security.demo.config;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pers.melii.cill.security.demo.dao.MenuMapper;
import pers.melii.cill.security.demo.dao.UserMapper;
import pers.melii.cill.security.demo.domain.LoginUser;
import pers.melii.cill.security.demo.domain.User;

import java.util.List;
import java.util.Objects;

/**
 * 自定义用户登录管理
 *
 * @author: ml
 * @date: 2022/9/12 22:32
 */
@Service
public class CustomUserDetailsManager implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private MenuMapper menuMapper;

    /**
     * 通过用户名进行登录
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 根据用户名获取用户信息
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUserName, username);
        User user = userMapper.selectOne(wrapper);

        // 如果查询不到数据就通过抛出异常来给出提示
        if (Objects.isNull(user)) {
            throw new UsernameNotFoundException(username);
        } else {
            // 根据用户查询权限信息，并添加到 loginUser 对象中
            List<String> perms = menuMapper.selectPermsByUserId(user.getId());
            // 封装成UserDetails对象返回
            return new LoginUser(user, perms);
        }
    }
}
