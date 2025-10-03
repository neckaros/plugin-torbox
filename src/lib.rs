use std::collections::{BTreeMap, HashMap};
use extism_pdk::*;
use rs_plugin_common_interfaces::{CredentialType, PluginInformation, PluginType, RsAudio, RsLookupQuery, RsLookupSourceResult, RsLookupWrapper, RsRequest, RsRequestFiles, RsRequestPluginRequest, RsRequestStatus, RsResolution, RsVideoCodec};
use serde::{Deserialize, Serialize, Deserializer};
use urlencoding::encode;



#[derive(Deserialize, Debug)]
struct ApiResponse {
    success: bool,
    error: Option<String>,
    detail: String,
    data: HashMap<String, TorrentInfo>,
}

#[derive(Deserialize, Debug, Clone)]
struct TorrentInfo {
    name: String,
    size: u64,
    hash: String,
    files: Vec<FileInfo>,
}


#[derive(Deserialize, Debug, Clone)]
struct FileInfo {
    name: String,
    size: u64,
    opensubtitles_hash: Option<String>,
    short_name: String,
    mimetype: String,
}


#[derive(Debug, Clone, Deserialize)]
pub struct MyTorrentsResponse {
    pub success: bool,
    pub error: Option<String>,
    pub detail: String,
    pub data: Vec<MyTorrent>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MyTorrent {
    pub id: i64,
    pub auth_id: String,
    pub server: i64,
    pub hash: String,
    pub name: String,
    pub magnet: Option<String>,
    pub size: u64,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
    pub download_state: String,
    pub seeds: i64,
    pub peers: i64,
    pub ratio: f64,
    pub progress: f64,
    pub download_speed: i64,
    pub upload_speed: i64,
    pub eta: i64,
    pub torrent_file: bool,
    pub expires_at: Option<String>,
    pub download_present: bool,
    pub files: Vec<MyFile>,
    pub download_path: String,
    pub availability: i64,
    pub download_finished: bool,
    pub tracker: Option<String>,
    pub total_uploaded: i64,
    pub total_downloaded: i64,
    pub cached: bool,
    pub owner: String,
    pub seed_torrent: bool,
    pub allow_zipped: bool,
    pub long_term_seeding: bool,
    pub tracker_message: Option<String>,
    pub cached_at: String,
    pub private: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MyFile {
    pub id: i64,
    pub md5: Option<String>,
    pub hash: String,
    pub name: String,
    pub size: u64,
    pub zipped: bool,
    pub s3_path: String,
    pub infected: bool,
    pub mimetype: String,
    pub short_name: String,
    pub absolute_path: String,
    pub opensubtitles_hash: Option<String>,
}



#[derive(Serialize)]
struct CreateBody {
    magnet: String,
}

#[derive(Deserialize)]
struct CreateTorrentResponse {
    success: bool,
    error: Option<String>,
    detail: String,
    data: CreateData,
}

#[derive(Deserialize)]
struct CreateData {
    torrent_id: i32,
}

#[derive(Deserialize)]
struct DownloadLinkResponse {
    success: bool,
    error: Option<String>,
    detail: String,
    data: String,
}

#[derive(Deserialize)]
struct SearchResponse {
    success: bool,
    error: Option<String>,
    data: Option<SearchData>,
}

#[derive(Deserialize)]
struct SearchData {
    torrents: Vec<Torrent>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum StringOrArray {
    Single(String),
    Array(Vec<String>),
}
#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum U32OrArray {
    Single(u32),
    Array(Vec<u32>),
}

#[derive(Deserialize, Debug)]
struct TitleParsedData {
    resolution: Option<String>,
    season: Option<U32OrArray>,
    episode: Option<U32OrArray>,
    codec: Option<String>,
    audio: Option<String>,
    language: Option<StringOrArray>,
    title: Option<String>,
    excess: Option<StringOrArray>,
    encoder: Option<String>,
}
#[derive(Deserialize, Debug)]
struct Torrent {
    hash: String,
    raw_title: String,
    title: String,
    title_parsed_data: TitleParsedData,
    magnet: Option<String>,
    torrent: Option<String>,
    last_known_seeders: u32,
    last_known_peers: u32,
    size: u64,
    tracker: String,
    categories: Vec<String>,
    files: u32,
    #[serde(rename = "type")]
    kind: String,
    nzb: Option<String>,
    age: String,
    user_search: bool,
    cached: bool,
}


#[plugin_fn]
pub fn infos() -> FnResult<Json<PluginInformation>> {
    Ok(Json(
        PluginInformation { name: "torbox".into(), capabilities: vec![PluginType::Lookup, PluginType::Request], version: 1, publisher: "neckaros".into(), repo: Some("https://github.com/neckaros/plugin-torbox".to_string()), description: "search and download torrent or usened from Torbox".into(), credential_kind: Some(CredentialType::Token), ..Default::default() }
    ))
}

#[plugin_fn]
pub fn process(Json(request): Json<RsRequestPluginRequest>) -> FnResult<Json<RsRequest>> {
    //log!(LogLevel::Info, "Some info! {:?}", request);

    if request.request.url.starts_with("magnet:") {
        if let Some(credentials) = request.credential {
            if let Some(password) = credentials.password {
               return handle_magnet_request(&request.request, &password);
            } else {
            return Err(WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401));
            }
        } else {
            return Err(WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401));
        }

    } else if request.request.url.starts_with("torbox://") {
        let token = &request.credential.and_then(|c| c.password)
            .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;
        let mut new_request = request.request.clone();
        new_request.url = new_request.url.replacen("torbox://", "https://", 1).replace("_TOKEN_", token);
        new_request.status = RsRequestStatus::FinalPrivate; // Direct download link
        new_request.permanent = false;      
        return Ok(Json(new_request));
    }

    Err(WithReturnCode::new(extism_pdk::Error::msg("Not supported"), 404))
}


#[plugin_fn]
pub fn request_permanent(Json(mut request): Json<RsRequestPluginRequest>) -> FnResult<Json<RsRequest>> {
    if request.request.url.starts_with("magnet") {
        let token = &request.credential.and_then(|c| c.password)
            .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;

        let torrent_info = check_instant(&request.request, token)?
            .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("Not available for instant download"), 404))?;
        if torrent_info.files.len() > 1 && request.request.selected_file.is_none() {
            let mut result = request.request.clone();
            result.status = RsRequestStatus::NeedFileSelection;
            result.permanent = false;
            result.files = Some(torrent_info.files.into_iter().map(|l| {
                let mut file = RsRequestFiles { name: l.short_name, size: l.size, mime: Some(l.mimetype), ..Default::default()};
                file.parse_filename();
                file
            }).collect());
            return Ok(Json(result));
        }

        // Check if already downloaded and cached
        let raw_hash = extract_btih_hash(&request.request.url)
            .ok_or_else(|| WithReturnCode(extism_pdk::Error::msg("Invalid magnet link: no BTIH hash found"), 400))?;
        let canonical_hash = get_canonical_hash(&raw_hash)?;
        let existing = get_my_torrents(token, 20)?.iter().find(|t| t.hash.eq_ignore_ascii_case(&canonical_hash)).cloned();
        if let Some(t) = existing {
            if t.cached {
                if let Some(file) = t.files.iter().find(|f| { f.short_name == request.request.selected_file.clone().unwrap_or_default() || f.name == request.request.selected_file.clone().unwrap_or_default() }) {
                    log!(LogLevel::Info, "File already cached: {}", file.name);
                    // Already cached, return direct download link
                    let mut new_request = request.request.clone();
                    new_request.url = format!("torbox://api.torbox.app/v1/api/torrents/requestdl?token=_TOKEN_&redirect=true&torrent_id={}&file_id={}", t.id, file.id);
                    new_request.status = RsRequestStatus::FinalPrivate; // Direct download link
                    new_request.permanent = true;      
                    return Ok(Json(new_request));
                }
            }
        }


        let url = get_file_download_url(&request.request, &torrent_info, token, true)?;
        let mut final_request = request.request.clone();
        final_request.url = url;
        final_request.status = RsRequestStatus::FinalPrivate;
        final_request.permanent = true;
        final_request.mime = Some("applications/torbox".to_owned());
        Ok(Json(final_request))
    } else if request.request.url.starts_with("https://api.torbox.app/v1/api/torrents/requestdl") {
        let token = &request.credential.and_then(|c| c.password)
            .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;
        let mut new_request = request.request.clone();
        new_request.url = request.request.url.replacen("https://", "torbox://", 1).replace(token, "_TOKEN_");
        new_request.status = RsRequestStatus::FinalPrivate; // Direct download link
        new_request.permanent = true;      
        return Ok(Json(new_request));
    } else {
        Err(WithReturnCode::new(extism_pdk::Error::msg("Not supported"), 404))
    }
}

#[plugin_fn]
pub fn lookup(Json(lookup): Json<RsLookupWrapper>) -> FnResult<Json<RsLookupSourceResult>> {

    let token = if let Some(cred) = &lookup.credential {
        if let Some(pw) = &cred.password {
            pw
        } else {
            return Ok(Json(RsLookupSourceResult::NotApplicable));
        }
    } else {
        return Ok(Json(RsLookupSourceResult::NotApplicable));
    };

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));

    let (search_query, season_episode) = get_search_query_and_params(&lookup.query);
    log!(LogLevel::Info, "Search query:\nfrom: {:?}\nto: {:?} / {:?}", lookup, search_query, season_episode);
    if search_query.is_empty() {
        return Ok(Json(RsLookupSourceResult::NotApplicable));
    }

    let api_url = if search_query.contains(':') {
        let base = "https://search-api.torbox.app/torrents/".to_string();
        let mut url = format!("{}{}?metadata=false&check_cache=true", base, encode(&search_query));
        if let Some((season, episode)) = season_episode {
            url.push_str(&format!("&season={}", season));
            if let Some(ep) = episode {
                url.push_str(&format!("&episode={}", ep));
            }
        }
        url
    } else {
        format!("https://search-api.torbox.app/v1/search?query={}&limit=20", encode(&search_query))
    };

    let req = HttpRequest {
        url: api_url.clone(),
        headers,
        method: Some("GET".into()),
    };
    log!(LogLevel::Info, "Search query request:\nfrom: {}", api_url);
    let res = http::request::<()>(&req, None)?;

    if res.status_code() != 200 {
        log!(LogLevel::Error, "HTTP error ({}) {}: {}", api_url, res.status_code(), String::from_utf8_lossy(&res.body()));
        return Ok(Json(RsLookupSourceResult::NotFound));
    }

    let response: SearchResponse = res.json()
        .map_err(|e| WithReturnCode(extism_pdk::Error::msg(format!("JSON search parse error: {}\nBody:\n{}", e, String::from_utf8(res.body()).unwrap_or("no body".to_string()))), 500))?;

    if response.success != true || response.data.is_none() {
        log!(LogLevel::Error, "API error ({}): {:?}", api_url, response.error);
        return Ok(Json(RsLookupSourceResult::NotFound));
    }

    let mut requests = Vec::new();
    for t in response.data.unwrap().torrents {
        if t.cached {
            let magnet = t.magnet.clone().unwrap_or_else(|| {
                format!("magnet:?xt=urn:btih:{}&dn={}", t.hash, encode(&t.title))
            });

            let mut r = RsRequest {
                url: magnet,
                permanent: false,
                filename: Some(t.raw_title.clone()),
                language: t.title_parsed_data.language.as_ref().and_then(|l| match l {
                    StringOrArray::Single(s) => Some(s.clone()),
                    StringOrArray::Array(vs) => Some(vs.join(", ")),
                }),
                season: t.title_parsed_data.season.as_ref().and_then(|s| match s {
                    U32OrArray::Single(v) => Some(*v),
                    U32OrArray::Array(vs) => vs.first().cloned(),
                }),
                episode: t.title_parsed_data.episode.as_ref().and_then(|s| match s {
                    U32OrArray::Single(v) => Some(*v),
                    U32OrArray::Array(vs) => vs.first().cloned(),
                }),
                videocodec: t.title_parsed_data.codec.as_ref().map(|a| match RsVideoCodec::from_filename(a) {
                    RsVideoCodec::Unknown => RsVideoCodec::Custom(a.clone()),
                    other => other,
                }),
                audio: t.title_parsed_data.audio.as_ref().map(|a| match RsAudio::from_filename(a) {
                    RsAudio::Unknown => RsAudio::Custom(a.clone()),
                    other => other,
                }).map(|a| vec![a]),
                resolution: t.title_parsed_data.resolution.as_ref().map(|a| match RsResolution::from_filename(a) {
                    RsResolution::Unknown => RsResolution::Custom(a.clone()),
                    other => other,
                }),
                size: Some(t.size),
                ..Default::default()
            };
            // TODO: Set resolution, codec from quality if parsed
            requests.push(r);
        }
    }

    if requests.is_empty() {
        Ok(Json(RsLookupSourceResult::NotFound))
    } else {
        Ok(Json(RsLookupSourceResult::Requests(requests)))
    }
}

fn get_search_query_and_params(query: &RsLookupQuery) -> (String, Option<(u32, Option<u32>)>) {
    match query {
        RsLookupQuery::Movie(m) => {
            if let Some(ids) = &m.ids {
                if let Some(id_str) = ids.imdb.as_ref().map(|u| format!("imdb:{}", u))
                    .or(ids.tmdb.map(|s| format!("tmdb:{}", s)))
                    .or(ids.tvdb.map(|u| format!("tvdb:{}", u))) {
                    return (id_str, None);
                }
            }
            (m.name.clone(), None)
        },
        RsLookupQuery::Episode(e) => {
            let ep_num = e.number.unwrap_or(1);
            let base_query = format!("{} S{:02}E{:02}", e.serie, e.season, ep_num);
            if let Some(ids) = &e.ids {
                if let Some(id_str) = ids.imdb.as_ref().map(|u| format!("imdb:{}", u))
                    .or(ids.tmdb.map(|s| format!("tmdb:{}", s)))
                    .or(ids.tvdb.map(|u| format!("tvdb:{}", u))) {
                    return (id_str, Some((e.season, Some(ep_num))));
                }
            }
            (base_query, None)
        },
        RsLookupQuery::SerieSeason(s) => {
            if let Some(ids) = &s.ids {
                if let Some(id_str) = ids.imdb.as_ref().map(|u| format!("imdb:{}", u))
                    .or(ids.tmdb.map(|s| format!("tmdb:{}", s)))
                    .or(ids.tvdb.map(|u| format!("tvdb:{}", u))) {
                    return (id_str, Some((s.name.parse().unwrap_or(1), None))); // Assume season from name or default
                }
            }
            (format!("{} season", s.name), None)
        },
        _ => (String::new(), None),
    }
}


fn handle_magnet_request(request: &RsRequest, password: &str) -> FnResult<Json<RsRequest>> {
    match check_instant(request, password)? {
        Some(torrent_info) => {
            if torrent_info.files.len() > 1 && request.selected_file.is_none() {
                let mut result = request.clone();
                result.status = RsRequestStatus::NeedFileSelection;
                result.files = Some(torrent_info.files.into_iter().map(|l| {
                let mut file = RsRequestFiles { name: l.short_name, size: l.size, mime: Some(l.mimetype), ..Default::default()};
                    file.parse_filename();
                    file
                }).collect());
                result.parse_subfilenames();
                Ok(Json(result))
            } else {
                // instant available, get file download URL
                let download_url = get_file_download_url(request, &torrent_info, password, true)?.replace("torbox://", "https://").replace("_TOKEN_", password);

                let mut new_request = request.clone();
                new_request.status = RsRequestStatus::FinalPrivate;
                new_request.url = download_url;
                new_request.permanent = false;
                Ok(Json(new_request))
            }
        },
        None => {
            // not available
            Err(WithReturnCode::new(extism_pdk::Error::msg("Not available for instant download"), 404))
        }
    }
}



fn extract_btih_hash(magnet: &str) -> Option<String> {
    if !magnet.starts_with("magnet:?") {
        return None;
    }
    let query = &magnet[8..]; // Skip "magnet:?"
    for part in query.split('&') {
        if part.starts_with("xt=urn:btih:") {
            return Some(part[12..].to_string()); // Skip "xt=urn:btih:"
        }
    }
    None
}

fn base32_decode(s: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buffer: u32 = 0;
    let mut bits_left: u32 = 0;
    let mut result = Vec::new();
    for &byte in s.as_bytes() {
        if let Some(pos) = alphabet.iter().position(|&x| x == byte) {
            let val = pos as u32;
            buffer = (buffer << 5) | val;
            bits_left += 5;
            if bits_left >= 8 {
                let byte_val = ((buffer >> (bits_left - 8)) & 0xFF) as u8;
                result.push(byte_val);
                bits_left -= 8;
            }
        } else {
            return vec![];
        }
    }
    if bits_left != 0 {
        return vec![];
    }
    result
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

fn get_canonical_hash(raw_hash: &str) -> FnResult<String> {
    if raw_hash.is_empty() {
        return Err(WithReturnCode(extism_pdk::Error::msg("Invalid BTIH hash"), 400));
    }
    let hash = if raw_hash.len() == 40 {
        raw_hash.to_lowercase()
    } else if raw_hash.len() == 32 {
        let bytes = base32_decode(&raw_hash.to_uppercase());
        if bytes.len() != 20 {
            return Err(WithReturnCode(extism_pdk::Error::msg("Invalid base32 BTIH hash"), 400));
        }
        bytes_to_hex(&bytes)
    } else {
        return Err(WithReturnCode(extism_pdk::Error::msg("Invalid BTIH hash length"), 400));
    };
    Ok(hash)
}

fn check_instant(request: &RsRequest, token: &str) -> FnResult<Option<TorrentInfo>> {
    let raw_hash = extract_btih_hash(&request.url)
        .ok_or_else(|| WithReturnCode(extism_pdk::Error::msg("Invalid magnet link: no BTIH hash found"), 400))?;
    let canonical_hash = get_canonical_hash(&raw_hash)?;

    let encoded_hash = encode(&canonical_hash);

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));

    let req = HttpRequest {
        url: format!("https://api.torbox.app/v1/api/torrents/checkcached?hash={}&format=object&list_files=true", encoded_hash),
        headers,
        method: Some("GET".into()),
    };

    let res = http::request::<()>(&req, None)?;

    if res.status_code() != 200 {
        let error_msg = String::from_utf8_lossy(&res.body()).to_string();
        return Err(WithReturnCode(extism_pdk::Error::msg(format!("HTTP {}: {}", res.status_code(), error_msg)), res.status_code() as i32));
    }

    let response: ApiResponse = res.json()
        .map_err(|e| WithReturnCode(extism_pdk::Error::msg(format!("JSON check instant result parse error: {}\nBody:\n {}", e, String::from_utf8(res.body()).unwrap_or("no body".to_string()))), 500))?;

    if let Some(err_msg) = response.error {
        return Err(WithReturnCode(extism_pdk::Error::msg(err_msg), 500));
    }

    Ok(if response.success {
        response.data.get(&canonical_hash).cloned()
    } else {
        None
    })
}


fn get_my_torrents(token: &str, limit: i32) -> FnResult<Vec<MyTorrent>> {
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));

    let req = HttpRequest {
        url: format!("https://api.torbox.app/v1/api/torrents/mylist?limit={}", limit),
        headers,
        method: Some("GET".into()),
    };

    let res = http::request::<()>(&req, None)?;

    if res.status_code() != 200 {
        let error_msg = String::from_utf8_lossy(&res.body()).to_string();
        return Err(WithReturnCode(extism_pdk::Error::msg(format!("HTTP error getting my torrent list {}: {}", res.status_code(), error_msg)), res.status_code() as i32));
    }

    let response: MyTorrentsResponse = res.json()
        .map_err(|e| WithReturnCode(extism_pdk::Error::msg(format!("JSON check instant result parse error: {}\nBody:\n {}", e, String::from_utf8(res.body()).unwrap_or("no body".to_string()))), 500))?;

   Ok(response.data)
}

fn get_file_download_url(request: &RsRequest, torrent_info: &TorrentInfo, token: &str, permanent: bool) -> FnResult<String> {
    let raw_hash = extract_btih_hash(&request.url)
        .ok_or_else(|| WithReturnCode(extism_pdk::Error::msg("Invalid magnet link: no BTIH hash found"), 400))?;
    let canonical_hash = get_canonical_hash(&raw_hash)?;

    let encoded_hash = encode(&canonical_hash);

    let files = &torrent_info.files;

    if files.is_empty() {
        return Err(WithReturnCode(extism_pdk::Error::msg("No files found in torrent"), 404));
    }

    // Select file index (0-based)
    let file_index: usize = if let Some(sel) = &request.selected_file {
        if let Ok(fid) = sel.parse::<usize>() {
            if fid == 0 || fid > files.len() {
                return Err(WithReturnCode(extism_pdk::Error::msg("Invalid file ID"), 400));
            }
            fid - 1
        } else {
            files.iter().position(|f| f.short_name == *sel || f.name == *sel)
                .ok_or_else(|| WithReturnCode(extism_pdk::Error::msg("Selected file not found"), 404))?
        }
    } else {
        files.iter()
            .enumerate()
            .max_by_key(|(_, f)| f.size)
            .map(|(i, _)| i)
            .unwrap_or(0)
    };

    let file_id = (file_index) as i32;

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));

    // Create torrent to get ID (form data)
    let magnet_encoded = encode(&request.url);
    let body_str = format!("magnet={}&add_only_if_cached=true", magnet_encoded);
    let body_vec = body_str.as_bytes().to_vec();

    let mut create_headers = headers.clone();
    create_headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());

    let create_req = HttpRequest {
        url: "https://api.torbox.app/v1/api/torrents/createtorrent".to_string(),
        headers: create_headers,
        method: Some("POST".into()),
    };

    let create_res = http::request::<Vec<u8>>(&create_req, Some(body_vec))?;

    if create_res.status_code() != 200 {
        let error_msg = String::from_utf8_lossy(&create_res.body()).to_string();
        return Err(WithReturnCode(extism_pdk::Error::msg(format!("Create torrent HTTP {}: {}\nBody:\n {}", create_res.status_code(), error_msg, String::from_utf8(create_res.body()).unwrap_or("no body".to_string()))), create_res.status_code() as i32));
    }

    let create_response: CreateTorrentResponse = create_res.json()
        .map_err(|e| WithReturnCode(extism_pdk::Error::msg(format!("JSON parse error during create torrent ({}): {}", create_req.url, e)), 500))?;

    if let Some(err_msg) = create_response.error {
        return Err(WithReturnCode(extism_pdk::Error::msg(err_msg), 500));
    }

    let torrent_id = create_response.data.torrent_id;

    if permanent {
        // For permanent requests, we are done here
        return Ok(format!("torbox://api.torbox.app/v1/api/torrents/requestdl?token=_TOKEN_&redirect=true&torrent_id={}&file_id={}", torrent_id, file_id));
    }
    // Request download link
    let dl_req = HttpRequest {
        url: format!("https://api.torbox.app/v1/api/torrents/requestdl?token={}&redirect=false&torrent_id={}&file_id={}", token, torrent_id, file_id),
        headers,
        method: Some("GET".into()),
    };

    let dl_res = http::request::<()>(&dl_req, None)?;

    if dl_res.status_code() != 200 {
        let error_msg = String::from_utf8_lossy(&dl_res.body()).to_string();
        return Err(WithReturnCode(extism_pdk::Error::msg(format!("Request dl HTTP({}) {}: {}", dl_req.url, dl_res.status_code(), error_msg)), dl_res.status_code() as i32));
    }

    let dl_response: DownloadLinkResponse = dl_res.json()
        .map_err(|e| WithReturnCode(extism_pdk::Error::msg(format!("JSON parse error during request dl ({}): {}", dl_req.url, e)), 500))?;

    if let Some(err_msg) = dl_response.error {
        return Err(WithReturnCode(extism_pdk::Error::msg(err_msg), 500));
    }

    Ok(dl_response.data)
}



