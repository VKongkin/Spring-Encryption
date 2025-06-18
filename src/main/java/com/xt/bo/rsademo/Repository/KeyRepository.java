package com.xt.bo.rsademo.Repository;

import com.xt.bo.rsademo.models.Key;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KeyRepository extends JpaRepository<Key,Integer> {
}
