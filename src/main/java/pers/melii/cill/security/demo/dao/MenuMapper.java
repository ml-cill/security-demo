package pers.melii.cill.security.demo.dao;


import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;
import pers.melii.cill.security.demo.domain.Menu;

import java.util.List;

/**
 * MenuMapper
 */
public interface MenuMapper extends BaseMapper<Menu> {

    List<String> selectPermsByUserId(@Param("userId") Long userId);

}
