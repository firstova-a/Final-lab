using JwtTest.EF;
using JwtTest.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JwtTest.Helpers;
using Microsoft.AspNetCore.Identity;
using Isopoh.Cryptography.Argon2;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http;
using System.IO;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;

namespace JwtTest.Controllers
{
    public class AccountController : BaseController
    {


        public AccountController(JwtContext context, IOptions<AuthOptions> options, IHostEnvironment hostEnvironment)
        {
            this.context = context;
            this.options = options;
            this.hostEnvironment = hostEnvironment;
        }

        [HttpPost("/token")]
        public IActionResult Token(string username, string password)
        {
            var identity = GetIdentity(username, password);
            if (identity == null)
            {
                return BadRequest(new { errorText = "Invalid username or password." });
            }

            var now = DateTime.UtcNow;
            // создаем JWT-токен
            var jwt = new JwtSecurityToken(
                    issuer: options.Value.Issuer,
                    audience: options.Value.Audience,
                    notBefore: now,
                    claims: identity.Claims,
                    expires: now.Add(TimeSpan.FromMinutes(options.Value.Lifetime)),
                    signingCredentials: new SigningCredentials(options.Value.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
            var response = new
            {
                access_token = encodedJwt,
                username = identity.Name
            };
            return Json(response);
        }

        private ClaimsIdentity GetIdentity(string username, string password)
        {
            Person person = context.People.SingleOrDefault(x => x.Login == username);
            if (person != null && Argon2.Verify(person.PasswordHash, password))
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimsIdentity.DefaultNameClaimType, person.Login),
                    new Claim(ClaimsIdentity.DefaultRoleClaimType, Enum.GetName(person.Role))
                };
                ClaimsIdentity claimsIdentity =
                new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                return claimsIdentity;
            }
            // если пользователя не найдено
            return null;
        }

        private async Task<bool> RegisterUser(string username, string password, UserRole role, IFormFile file)
        {
            if (context.People.Any(p => p.Login == username))
                return false;
            string randomFile = null;
            if (file != null)
            {
                randomFile = $"{Path.GetRandomFileName()}.{Path.GetExtension(file.FileName)}";

            }
            Person person = new Person()
            {
                Login = username,
                PasswordHash = Argon2.Hash(password),
                Role = role,
                Avatar = randomFile
            };
            await context.People.AddAsync(person);
            await context.SaveChangesAsync();
            if (file != null)
            {
                person = context.Entry(person).Entity;
                string userPath = Path.Combine(ImageFolder, person.Id.ToString());
                if (!Directory.Exists(userPath))
                    Directory.CreateDirectory(userPath);
                await file.WriteToFile(Path.Combine(userPath, randomFile));
            }
            return true;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            if (await RegisterUser(model.Username, model.Password, UserRole.User, model.Avatar))
                return Redirect("/Home/Index");
            else
            {
                ModelState.AddModelError("Username", "Данное имя уже используется");
                return (View(model));
            }
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            Person person = context.People.SingleOrDefault(usr => usr.Login == model.Username);
            if (person == null || !Argon2.Verify(person.PasswordHash, model.Password))
            {
                ModelState.AddModelError("Username", "Неверное имя пользователя или пароль");
                return View(model);
            }
            await Authenticate(person.Login, person.Role);
            return Redirect("/Home/Index");
        }

        [Authorize]
        public async Task<IActionResult> LogOff()
        {
            await Logout();
            return Redirect("/Home/Index");
        }

        [Authorize(Roles = "Admin")]
        public IActionResult CreateUser()
        {
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateUser(UserModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            if (await RegisterUser(model.Username, model.Password, model.Role, model.Avatar))
                return Redirect("/Home/Index");
            else
            {
                ModelState.AddModelError("Username", "Данное имя уже используется");
                return (View(model));
            }
        }

        [Authorize(Roles = "Admin")]
        public IActionResult ListUsers()
        {
            return View(context.People);
        }

        [Authorize(Roles = "Admin")]
        public IActionResult EditUser(int id)
        {
            Person person = context.People.Find(id);
            return View(person.ToEditUserModel());
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> EditUser(EditUserModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            Person person = context.People.Find(model.Id);
            if (person != null)
            {
                bool taken = person.Login != model.Username && context.People.Any(p => p.Login == model.Username);
                if (taken)
                {
                    ModelState.AddModelError("Username", "Данное имя уже занято");
                    return (View(model));
                }
                if (model.Avatar != null)
                {
                    string userDir = Path.Combine(ImageFolder, person.Id.ToString());
                    if (person.Avatar != null)
                        System.IO.File.Delete(Path.Combine(userDir, person.Avatar));
                    else if (!Directory.Exists(userDir))
                        Directory.CreateDirectory(userDir);
                    person.Avatar = $"{Path.GetRandomFileName()}.{Path.GetExtension(model.Avatar.FileName)}";
                    await model.Avatar.WriteToFile(Path.Combine(userDir, person.Avatar));
                }
                person.Login = model.Username;
                if (!string.IsNullOrEmpty(model.NewPassword))
                    person.PasswordHash = Argon2.Hash(model.NewPassword);
                person.Role = model.Role;
                await context.SaveChangesAsync();
                return Redirect("/Home/Index");
            }
            else
            {
                ModelState.AddModelError("", "Неверный ID");
                return (View(model));
            }
        }

        [Authorize(Roles = "Admin")]
        public IActionResult UserDetails(int id)
        {
            Person person = context.People.Find(id);
            return View(person.ToUserModel());
        }


        [Authorize(Roles = "Admin")]
        public IActionResult DeleteUser(int id)
        {
            Person person = context.People.Find(id);
            return View(person.ToUserModel());
        }


        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DelUser(int id)
        {
            Person person = context.People.Find(id);
            if (person != null)
            {
                context.People.Remove(person);
                await context.SaveChangesAsync();
            }
            return Redirect("ListUsers");
        }

        [Authorize]
        public IActionResult Userpage()
        {
            UserModel usr = CurrentUser.ToUserModel();        
            return View(usr);
        }
        
        private string GetContentType(string filename)
        {
            string contentType;
            new FileExtensionContentTypeProvider().TryGetContentType(filename, out contentType);
            return contentType ?? "application/octet-stream";
        }

        [Authorize]
        public async Task<IActionResult> Avatar(string username)
        {
            Person person = context.People.FirstOrDefault(p => p.Login == username);

            string filePath;
            if (person == null || person.Avatar == null)
                filePath = Path.Combine(hostEnvironment.ContentRootPath, "DefaultImages", "no_ava.png");
            else
                filePath = Path.Combine(ImageFolder, person.Id.ToString(), person.Avatar);
            string contentType = GetContentType(filePath);
            byte[] imgBytes = await System.IO.File.ReadAllBytesAsync(filePath);
            return File(imgBytes, contentType);
        }
        
        
        [Authorize]
        public async Task<IActionResult> ListBlog()
        {
            UserModel usr = CurrentUser.ToUserModel();
            Person usrcont = context.People.FirstOrDefault(p => p.Login == usr.Username);
            List<Blog> blog = await context.Blogs.Where(element => element.Author.Id == usrcont.Id).ToListAsync();
            blog.Reverse();
            return View(blog);
        }
        
      
        public async Task<IActionResult> AllListBlog()
        {
            List<Blog> blog = await context.Blogs.ToListAsync();
            blog.Reverse();
            return View(blog);
        }
        
        [Authorize]
        public async Task<IActionResult> DeleteBlog(int id)
        {
            ClaimsIdentity cookieClaims = User.Identities.FirstOrDefault(cc => cc.AuthenticationType == "ApplicationCookie");
            bool authenticated = cookieClaims != null && cookieClaims.IsAuthenticated;
            if (authenticated)
            {
                Blog blog = context.Blogs.Find(id);
                if (blog != null)
                {
                    context.Blogs.Remove(blog);
                    await context.SaveChangesAsync();
                }
                Claim roleClaim = cookieClaims.Claims.FirstOrDefault(cc => cc.Type == cookieClaims.RoleClaimType);
                if (roleClaim.Value == "Admin")
                {
                    return Redirect("/Account/AllListBlog");
                } else if (roleClaim.Value == "User")
                {
                    return Redirect("/Account/ListBlog");
                }
            }
            return Redirect("/Account/AllListBlog");
        }
        
        
        [HttpGet]
        [Authorize(Roles = "User")]
        public IActionResult CreateBlog()
        {
            return View();
        }
        
        [HttpPost]
        
        public async Task<IActionResult> CreateBlog(BlogModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            if (await RegisterBlog(model.Bird, 
                                    model.BirdInLatin, 
                                    model.Count, 
                                    model.Time,
                                    model.Weather,
                                    model.Place,
                                    model.Comment,
                                    model.Picture))
                return Redirect("/Account/ListBlog");
            else
            {
                ModelState.AddModelError("Blog", "Произошла ошибка, пожалуйста повторите");
                return (View(model));
            }
        }
        
        private async Task<bool> RegisterBlog(string bird, 
                                                string birdInLatin, 
                                                int count, 
                                                DateTime time,
                                                string weather,
                                                string place,
                                                string comment,
                                                IFormFile file)
        {
            UserModel usr = CurrentUser.ToUserModel();
            Person usrcont = context.People.FirstOrDefault(p => p.Login == usr.Username);
            
            string randomFile = null;
            if (file != null)
            {
                randomFile = $"{Path.GetRandomFileName()}.{Path.GetExtension(file.FileName)}";
            }
            Blog blog = new Blog()
            {
                Bird = bird,
                BirdInLatin = birdInLatin,
                Count = count,
                Weather = weather,
                Time = time,
                Place = place,
                Comment = comment,
                Author = usrcont,
                Picture = randomFile
            };
            
            await context.Blogs.AddAsync(blog);
            await context.SaveChangesAsync();
            if (file != null)
            {
                blog = context.Entry(blog).Entity;
                string userPath = Path.Combine(ImageFolder, blog.Id.ToString());
                if (!Directory.Exists(userPath))
                    Directory.CreateDirectory(userPath);
                await file.WriteToFile(Path.Combine(userPath, randomFile));
            }
            return true;
        }
        
        
        public async Task<IActionResult> BirdPicture(string username)
        {
            Blog blog = context.Blogs.FirstOrDefault(p => p.Bird == username);

            string filePath;
            if (blog == null || blog.Picture == null)
                filePath = Path.Combine(hostEnvironment.ContentRootPath, "DefaultImages", "birdDefault.png");
            else
                filePath = Path.Combine(ImageFolder, blog.Id.ToString(), blog.Picture);
            string contentType = GetContentType(filePath);
            byte[] imgBytes = await System.IO.File.ReadAllBytesAsync(filePath);
            return File(imgBytes, contentType);
        }

        [HttpPost]
        public async Task<String> Login2(LoginModel model)
        {
            MainModel obj = new MainModel();
            if (!ModelState.IsValid) {
                obj.ErrorMessage = "НЕПРАВИЛЬНЫЕ ДАННЫЕ";
                var json2 = JsonConvert.SerializeObject(obj, Formatting.Indented, new JsonSerializerSettings()
                {
                    ReferenceLoopHandling = ReferenceLoopHandling.Ignore
                });
                return json2;
            }
            Person person = context.People.SingleOrDefault(usr => usr.Login == model.Username);
            if (person == null || !Argon2.Verify(person.PasswordHash, model.Password))
            {
                obj.ErrorMessage = "Неверное имя пользователя или пароль";
                ModelState.AddModelError("Username", "Неверное имя пользователя или пароль");
                var json3 = JsonConvert.SerializeObject(obj, Formatting.Indented, new JsonSerializerSettings()
                {
                    ReferenceLoopHandling = ReferenceLoopHandling.Ignore
                });
                return json3;
            }
            await Authenticate(person.Login, person.Role);
            IQueryable<Blog> blogs = from blog in context.Blogs
                                     select blog;
            obj.Blogs = await blogs.ToListAsync();
            obj.User = CurrentUser;
            var json = JsonConvert.SerializeObject(obj, Formatting.Indented, new JsonSerializerSettings()
            {
                ReferenceLoopHandling = ReferenceLoopHandling.Ignore
            });
            return json;
        }
       

        [HttpPost]
        [Authorize]
        public async Task<string> RegisterBlog2(string bird,
                                               string birdInLatin,
                                               int count,
                                              string time,
                                               string weather,
                                               string place,
                                               string comment)
        {
            UserModel usr = CurrentUser.ToUserModel();
            Person usrcont = context.People.FirstOrDefault(p => p.Login == usr.Username);
            DateTime ndat = DateTime.Parse(time);


            Blog blog = new Blog()
            {
                Bird = bird,
                BirdInLatin = birdInLatin,
                Count = count,
                Weather = weather,
                Time = ndat,
                Place = place,
                Comment = comment,
                Author = usrcont
                
            };

            await context.Blogs.AddAsync(blog);
            await context.SaveChangesAsync();
           
            MainModel obj = new MainModel();
            IQueryable<Blog> blogs = from blogall in context.Blogs
                                     select blogall;
            obj.Blogs = await blogs.ToListAsync();
            obj.User = CurrentUser;
            var json6 = JsonConvert.SerializeObject(obj, Formatting.Indented, new JsonSerializerSettings()
            {
                ReferenceLoopHandling = ReferenceLoopHandling.Ignore
            });
            return json6;
            
        }


        [Authorize]
        
        public async Task<string> DeleteBlog2(int id)
        {
            Blog blog = context.Blogs.Find(id);
            MainModel obj = new MainModel();
            Person qwe = blog.Author;
            Person asd = CurrentUser;
            if (blog != null && CurrentUser.Role == UserRole.User && blog.Author == CurrentUser)
            {
                context.Blogs.Remove(blog);
                await context.SaveChangesAsync();
            

            IQueryable<Blog> blogs = from blogall in context.Blogs
                                     select blogall;
            obj.Blogs = await blogs.ToListAsync();
            obj.ErrorMessage = null;
                obj.User = CurrentUser;
            }
            else if (blog != null && CurrentUser.Role == UserRole.Admin)
            {
                context.Blogs.Remove(blog);
                await context.SaveChangesAsync();
                IQueryable<Blog> blogs = from blogall in context.Blogs
                                         select blogall;
                obj.Blogs = await blogs.ToListAsync();
                obj.ErrorMessage = null;
                obj.User = CurrentUser;
            }
            else
            {
                obj.ErrorMessage = "Нельзя удалить";
            }
            var json7 = JsonConvert.SerializeObject(obj, Formatting.Indented, new JsonSerializerSettings()

            {
                ReferenceLoopHandling = ReferenceLoopHandling.Ignore
            });
            return json7;
        }


        [Authorize]
        [HttpGet]
        public async Task<String> Logoff2()
        {
            
                await HttpContext.SignOutAsync();
                var obj = new MainModel()
                {
                    User = CurrentUser,
                    ErrorMessage = null
                };
                var json = JsonConvert.SerializeObject(obj, Formatting.Indented,
                    new JsonSerializerSettings()
                    {
                        ReferenceLoopHandling = ReferenceLoopHandling.Ignore
                    });
                return json;
                    }

      
        [Authorize]
        public async Task<string> Refresh()
        {
            MainModel obj = new MainModel();
            IQueryable<Blog> blogs = from blogall in context.Blogs
                                     select blogall;
            obj.Blogs = await blogs.ToListAsync();
            var json6 = JsonConvert.SerializeObject(obj, Formatting.Indented, new JsonSerializerSettings()
            {
                ReferenceLoopHandling = ReferenceLoopHandling.Ignore
            });
            return json6;
        }


    }
}
