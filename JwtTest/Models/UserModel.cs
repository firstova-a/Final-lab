﻿using JwtTest.EF;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JwtTest.Models
{
    public class UserModel
    {
        public int? Id { get; set; }
        [Required(ErrorMessage = "Имя пользователя является обязательным")]
        [DisplayName("Имя пользователя")]
        public string Username { get; set; }
        [DisplayName("Пароль")]
        [Required(ErrorMessage = "Пароль является обязательным")]
        public string Password { get; set; }
        [DisplayName("Уровень доступа")]
        public UserRole Role { get; set; }
        [DisplayName("Загрузите Аватар")]
        [DataType(DataType.Upload)]
        public IFormFile Avatar { get; set; }
    }
}
