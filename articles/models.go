package articles

import (
	"strconv"
	"strings"

	"github.com/gothinkster/golang-gin-realworld-example-app/common"
	"github.com/gothinkster/golang-gin-realworld-example-app/users"
	"gorm.io/gorm"
)

type ArticleModel struct {
	gorm.Model
	Slug        string `gorm:"uniqueIndex"`
	Title       string
	Description string `gorm:"size:2048"`
	Body        string `gorm:"size:2048"`
	Author      ArticleUserModel
	AuthorID    uint
	Tags        []TagModel     `gorm:"many2many:article_tags;"`
	Comments    []CommentModel `gorm:"ForeignKey:ArticleID"`
}

type ArticleUserModel struct {
	gorm.Model
	UserModel      users.UserModel
	UserModelID    uint
	ArticleModels  []ArticleModel  `gorm:"ForeignKey:AuthorID"`
	FavoriteModels []FavoriteModel `gorm:"ForeignKey:FavoriteByID"`
}

type FavoriteModel struct {
	gorm.Model
	Favorite     ArticleModel
	FavoriteID   uint
	FavoriteBy   ArticleUserModel
	FavoriteByID uint
}

type TagModel struct {
	gorm.Model
	Tag           string         `gorm:"uniqueIndex"`
	ArticleModels []ArticleModel `gorm:"many2many:article_tags;"`
}

type CommentModel struct {
	gorm.Model
	Article   ArticleModel
	ArticleID uint
	Author    ArticleUserModel
	AuthorID  uint
	Body      string `gorm:"size:2048"`
}

func GetArticleUserModel(userModel users.UserModel) ArticleUserModel {
	var articleUserModel ArticleUserModel
	if userModel.ID == 0 {
		return articleUserModel
	}
	db := common.GetDB()
	db.Where(&ArticleUserModel{
		UserModelID: userModel.ID,
	}).FirstOrCreate(&articleUserModel)
	articleUserModel.UserModel = userModel
	return articleUserModel
}

// FindArticleUserModel is the read-only counterpart used by GET handlers and
// serializers. A read must not create an author/favorite identity row.
func FindArticleUserModel(userModel users.UserModel) ArticleUserModel {
	var articleUserModel ArticleUserModel
	if userModel.ID == 0 {
		return articleUserModel
	}
	common.GetDB().Where("user_model_id = ?", userModel.ID).First(&articleUserModel)
	articleUserModel.UserModel = userModel
	return articleUserModel
}

func (article ArticleModel) favoritesCount() uint {
	db := common.GetDB()
	var count int64
	db.Model(&FavoriteModel{}).Where(FavoriteModel{
		FavoriteID: article.ID,
	}).Count(&count)
	return uint(count)
}

func (article ArticleModel) isFavoriteBy(user ArticleUserModel) bool {
	if user.ID == 0 {
		return false
	}
	db := common.GetDB()
	var favorite FavoriteModel
	db.Where(FavoriteModel{
		FavoriteID:   article.ID,
		FavoriteByID: user.ID,
	}).First(&favorite)
	return favorite.ID != 0
}

// BatchGetFavoriteCounts returns a map of article ID to favorite count
func BatchGetFavoriteCounts(articleIDs []uint) map[uint]uint {
	if len(articleIDs) == 0 {
		return make(map[uint]uint)
	}
	db := common.GetDB()

	type result struct {
		FavoriteID uint
		Count      uint
	}
	var results []result
	db.Model(&FavoriteModel{}).
		Select("favorite_id, COUNT(*) as count").
		Where("favorite_id IN ?", articleIDs).
		Group("favorite_id").
		Find(&results)

	countMap := make(map[uint]uint)
	for _, r := range results {
		countMap[r.FavoriteID] = r.Count
	}
	return countMap
}

// BatchGetFavoriteStatus returns a map of article ID to whether the user favorited it
func BatchGetFavoriteStatus(articleIDs []uint, userID uint) map[uint]bool {
	if len(articleIDs) == 0 || userID == 0 {
		return make(map[uint]bool)
	}
	db := common.GetDB()

	var favorites []FavoriteModel
	db.Where("favorite_id IN ? AND favorite_by_id = ?", articleIDs, userID).Find(&favorites)

	statusMap := make(map[uint]bool)
	for _, f := range favorites {
		statusMap[f.FavoriteID] = true
	}
	return statusMap
}

func (article ArticleModel) favoriteBy(user ArticleUserModel) error {
	db := common.GetDB()
	var favorite FavoriteModel
	err := db.FirstOrCreate(&favorite, &FavoriteModel{
		FavoriteID:   article.ID,
		FavoriteByID: user.ID,
	}).Error
	return err
}

func (article ArticleModel) unFavoriteBy(user ArticleUserModel) error {
	db := common.GetDB()
	err := db.Where("favorite_id = ? AND favorite_by_id = ?", article.ID, user.ID).Delete(&FavoriteModel{}).Error
	return err
}

func SaveOne(data interface{}) error {
	db := common.GetDB()
	err := db.Save(data).Error
	return err
}

func FindOneArticle(condition interface{}) (ArticleModel, error) {
	db := common.GetDB()
	var model ArticleModel
	err := db.Preload("Author.UserModel").Preload("Tags").Where(condition).First(&model).Error
	return model, err
}

func FindOneComment(condition *CommentModel) (CommentModel, error) {
	db := common.GetDB()
	var model CommentModel
	err := db.Preload("Author.UserModel").Preload("Article").Where(condition).First(&model).Error
	return model, err
}

func (self *ArticleModel) getComments() error {
	db := common.GetDB()
	err := db.Preload("Author.UserModel").Model(self).Association("Comments").Find(&self.Comments)
	return err
}

func getAllTags() ([]TagModel, error) {
	db := common.GetDB()
	var models []TagModel
	err := db.Find(&models).Error
	return models, err
}

const maxArticlePageSize = 100
const maxArticleOffset = 10000

func articlePagination(limit, offset string) (int, int) {
	pageSize, err := strconv.Atoi(strings.TrimSpace(limit))
	if err != nil || pageSize < 1 {
		pageSize = 20
	}
	if pageSize > maxArticlePageSize {
		pageSize = maxArticlePageSize
	}
	start, err := strconv.Atoi(strings.TrimSpace(offset))
	if err != nil || start < 0 {
		start = 0
	}
	if start > maxArticleOffset {
		start = maxArticleOffset
	}
	return pageSize, start
}

func FindManyArticle(tag, author, limit, offset, favorited string) ([]ArticleModel, int, error) {
	db := common.GetDB()
	var models []ArticleModel
	var count int

	limit_int, offset_int := articlePagination(limit, offset)

	tx := db.Begin()
	if tag != "" {
		var tagModel TagModel
		tx.Where(TagModel{Tag: tag}).First(&tagModel)
		if tagModel.ID != 0 {
			// Get article IDs via association
			var tempModels []ArticleModel
			if err := tx.Model(&tagModel).Offset(offset_int).Limit(limit_int).Association("ArticleModels").Find(&tempModels); err != nil {
				tx.Rollback()
				return models, count, err
			}
			count = int(tx.Model(&tagModel).Association("ArticleModels").Count())
			// Fetch articles with preloaded associations in single query, ordered by updated_at desc
			if len(tempModels) > 0 {
				var ids []uint
				for _, m := range tempModels {
					ids = append(ids, m.ID)
				}
				tx.Preload("Author.UserModel").Preload("Tags").Where("id IN ?", ids).Order("updated_at desc").Find(&models)
			}
		}
	} else if author != "" {
		var userModel users.UserModel
		tx.Where(users.UserModel{Username: author}).First(&userModel)
		articleUserModel := FindArticleUserModel(userModel)

		if articleUserModel.ID != 0 {
			count = int(tx.Model(&articleUserModel).Association("ArticleModels").Count())
			// Get article IDs via association
			var tempModels []ArticleModel
			if err := tx.Model(&articleUserModel).Offset(offset_int).Limit(limit_int).Association("ArticleModels").Find(&tempModels); err != nil {
				tx.Rollback()
				return models, count, err
			}
			// Fetch articles with preloaded associations in single query, ordered by updated_at desc
			if len(tempModels) > 0 {
				var ids []uint
				for _, m := range tempModels {
					ids = append(ids, m.ID)
				}
				tx.Preload("Author.UserModel").Preload("Tags").Where("id IN ?", ids).Order("updated_at desc").Find(&models)
			}
		}
	} else if favorited != "" {
		var userModel users.UserModel
		tx.Where(users.UserModel{Username: favorited}).First(&userModel)
		articleUserModel := FindArticleUserModel(userModel)
		if articleUserModel.ID != 0 {
			var favoriteModels []FavoriteModel
			tx.Where(FavoriteModel{
				FavoriteByID: articleUserModel.ID,
			}).Offset(offset_int).Limit(limit_int).Find(&favoriteModels)

			count = int(tx.Model(&articleUserModel).Association("FavoriteModels").Count())
			// Batch fetch articles to avoid N+1 query
			if len(favoriteModels) > 0 {
				var ids []uint
				for _, favorite := range favoriteModels {
					ids = append(ids, favorite.FavoriteID)
				}
				tx.Preload("Author.UserModel").Preload("Tags").Where("id IN ?", ids).Order("updated_at desc").Find(&models)
			}
		}
	} else {
		var count64 int64
		tx.Model(&ArticleModel{}).Count(&count64)
		count = int(count64)
		tx.Offset(offset_int).Limit(limit_int).Preload("Author.UserModel").Preload("Tags").Find(&models)
	}

	err := tx.Commit().Error
	return models, count, err
}

func (self *ArticleUserModel) GetArticleFeed(limit, offset string) ([]ArticleModel, int, error) {
	db := common.GetDB()
	models := make([]ArticleModel, 0)
	var count int

	limit_int, offset_int := articlePagination(limit, offset)

	tx := db.Begin()
	followings := self.UserModel.GetFollowings()

	// Batch get ArticleUserModel IDs to avoid N+1 query
	if len(followings) > 0 {
		var followingUserIDs []uint
		for _, following := range followings {
			followingUserIDs = append(followingUserIDs, following.ID)
		}

		var articleUserModels []ArticleUserModel
		tx.Where("user_model_id IN ?", followingUserIDs).Find(&articleUserModels)

		var authorIDs []uint
		for _, aum := range articleUserModels {
			authorIDs = append(authorIDs, aum.ID)
		}

		if len(authorIDs) > 0 {
			var count64 int64
			tx.Model(&ArticleModel{}).Where("author_id IN ?", authorIDs).Count(&count64)
			count = int(count64)
			tx.Preload("Author.UserModel").Preload("Tags").Where("author_id IN ?", authorIDs).Order("updated_at desc").Offset(offset_int).Limit(limit_int).Find(&models)
		}
	}

	err := tx.Commit().Error
	return models, count, err
}

func (model *ArticleModel) setTags(tags []string) error {
	return model.setTagsUsing(common.GetDB(), tags)
}

func (model *ArticleModel) setTagsUsing(db *gorm.DB, tags []string) error {
	if len(tags) == 0 {
		model.Tags = []TagModel{}
		return nil
	}

	// Batch fetch existing tags
	var existingTags []TagModel
	if err := db.Where("tag IN ?", tags).Find(&existingTags).Error; err != nil {
		return err
	}

	// Create a map for quick lookup
	existingTagMap := make(map[string]TagModel)
	for _, t := range existingTags {
		existingTagMap[t.Tag] = t
	}

	// Create missing tags and build final list
	var tagList []TagModel
	for _, tag := range tags {
		if _, seen := existingTagMap[tag]; seen {
			// Existing and repeated input tags should appear only once.
			if len(tagList) > 0 {
				duplicate := false
				for _, item := range tagList {
					if item.Tag == tag {
						duplicate = true
						break
					}
				}
				if duplicate {
					continue
				}
			}
		}
		if existing, ok := existingTagMap[tag]; ok {
			tagList = append(tagList, existing)
		} else {
			// Create new tag with race condition handling
			newTag := TagModel{Tag: tag}
			if err := db.Create(&newTag).Error; err != nil {
				// If creation failed (e.g., concurrent insert), try to fetch existing
				var existing TagModel
				if err2 := db.Where("tag = ?", tag).First(&existing).Error; err2 == nil {
					tagList = append(tagList, existing)
					continue
				}
				return err
			}
			tagList = append(tagList, newTag)
			existingTagMap[tag] = newTag
		}
	}
	model.Tags = tagList
	return nil
}

func SaveArticleWithTags(model *ArticleModel, tags []string) error {
	return common.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := model.setTagsUsing(tx, tags); err != nil {
			return err
		}
		return tx.Save(model).Error
	})
}

func (model *ArticleModel) UpdateWithTags(data ArticleModel, tags []string) error {
	return common.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := data.setTagsUsing(tx, tags); err != nil {
			return err
		}
		if err := tx.Model(model).Omit("Tags").Updates(data).Error; err != nil {
			return err
		}
		if err := tx.Model(model).Association("Tags").Replace(data.Tags); err != nil {
			return err
		}
		return tx.Preload("Tags").First(model, model.ID).Error
	})
}

func (model *ArticleModel) Update(data interface{}) error {
	db := common.GetDB()
	err := db.Model(model).Updates(data).Error
	return err
}

func DeleteArticleModel(condition interface{}) error {
	db := common.GetDB()
	err := db.Where(condition).Delete(&ArticleModel{}).Error
	return err
}

func DeleteCommentModel(condition interface{}) error {
	db := common.GetDB()
	err := db.Where(condition).Delete(&CommentModel{}).Error
	return err
}
