use std::collections::{BTreeMap, HashMap};
use extism_pdk::*;
use rs_plugin_common_interfaces::{CredentialType, PluginInformation, PluginType, RsAudio, RsResolution, RsVideoCodec};
use rs_plugin_common_interfaces::lookup::{RsLookupQuery, RsLookupSourceResult, RsLookupWrapper};
use rs_plugin_common_interfaces::request::{RsRequest, RsRequestFiles, RsRequestPluginRequest, RsRequestStatus, RsProcessingActionRequest, RsRequestAddResponse, RsProcessingProgress, RsProcessingStatus};
use serde::Deserialize;
use urlencoding::encode;



#[derive(Deserialize, Debug)]
struct ApiResponse {
    success: bool,
    error: Option<String>,
    //detail: String,
    data: HashMap<String, TorrentInfo>,
}

#[derive(Deserialize, Debug, Clone)]
struct TorrentInfo {
    //name: String,
    //size: u64,
    //hash: String,
    files: Option<Vec<FileInfo>>,
}


#[derive(Deserialize, Debug, Clone)]
struct FileInfo {
    //name: String,
    size: i64,
    //opensubtitles_hash: Option<String>,
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
pub struct MyTorrentResponse {
    pub success: bool,
    pub error: Option<String>,
    pub detail: String,
    pub data: MyTorrent,
}


#[derive(Debug, Clone, Deserialize)]
pub struct MyTorrent {
    pub id: i64,
    pub auth_id: String,
    pub server: i64,
    pub hash: String,
    pub name: String,
    pub magnet: Option<String>,
    pub size: Option<i64>,
    // pub active: bool,
    // pub created_at: String,
    // pub updated_at: String,
    pub download_state: Option<String>,
    // pub seeds: i64,
    // pub peers: i64,
    // pub ratio: f64,
    pub progress: Option<f64>,
    // pub download_speed: i64,
    // pub upload_speed: i64,
    pub eta: Option<i64>,
    // pub torrent_file: bool,
    // pub expires_at: Option<String>,
    // pub download_present: bool,
    pub files: Option<Vec<MyFile>>,
    // pub download_path: String,
    // pub availability: i64,
    pub download_finished: Option<bool>,
    // pub tracker: Option<String>,
    // pub total_uploaded: i64,
    // pub total_downloaded: i64,
    pub cached: bool,
    // pub owner: String,
    // pub seed_torrent: bool,
    // pub allow_zipped: bool,
    // pub long_term_seeding: bool,
    // pub tracker_message: Option<String>,
    // pub cached_at: String,
    // pub private: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MyFile {
    pub id: i64,
    pub md5: Option<String>,
    pub hash: String,
    pub name: String,
    pub size: i64,
    pub zipped: bool,
    pub s3_path: String,
    pub infected: bool,
    pub mimetype: String,
    pub short_name: String,
    pub absolute_path: String,
    pub opensubtitles_hash: Option<String>,
}


/*
#[derive(Serialize)]
struct CreateBody {
    magnet: String,
} */

#[derive(Deserialize)]
struct CreateTorrentResponse {
    //success: bool,
    error: Option<String>,
    //detail: String,
    data: CreateData,
}

#[derive(Deserialize)]
struct CreateData {
    torrent_id: i32,
}

#[derive(Deserialize)]
struct DownloadLinkResponse {
    //success: bool,
    error: Option<String>,
    //detail: String,
    data: String,
}

#[derive(Deserialize)]
struct ControlTorrentResponse {
    success: bool,
    error: Option<String>,
    detail: String,
}

#[derive(Deserialize)]
struct TorboxStatusResponse {
    success: Option<bool>,
    error: Option<String>,
    detail: Option<String>,
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
    //title: Option<String>,
    //excess: Option<StringOrArray>,
    //encoder: Option<String>,
}
#[derive(Deserialize, Debug)]
struct Torrent {
    hash: String,
    raw_title: String,
    title: String,
    title_parsed_data: TitleParsedData,
    magnet: Option<String>,
    //torrent: Option<String>,
    //last_known_seeders: u32,
    //last_known_peers: u32,
    size: i64,
    //tracker: String,
    //categories: Vec<String>,
    //files: u32,
    //#[serde(rename = "type")]
    //kind: String,
    //nzb: Option<String>,
    //age: String,
    //user_search: bool,
    cached: bool,
}


#[plugin_fn]
pub fn infos() -> FnResult<Json<PluginInformation>> {
    Ok(Json(
        PluginInformation { name: "torbox".into(), capabilities: vec![PluginType::Lookup, PluginType::Request], version: 5, publisher: "neckaros".into(), repo: Some("https://github.com/neckaros/plugin-torbox".to_string()), description: "search and download torrent or usened from Torbox".into(), credential_kind: Some(CredentialType::Token), ..Default::default() }
    ))
}

#[plugin_fn]
pub fn check_instant(Json(request): Json<RsRequestPluginRequest>) -> FnResult<Json<bool>> {
    // torbox:// URLs are already processed and always instant
    if request.request.url.starts_with("torbox://") {
        return Ok(Json(true));
    }

    // Only magnet links can be checked for instant availability
    if !request.request.url.starts_with("magnet:") {
        return Ok(Json(false));
    }

    let token = request.credential
        .and_then(|c| c.password)
        .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;

    let result = check_instant_internal(&request.request, &token)?;
    Ok(Json(result.is_some()))
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
        new_request.status = RsRequestStatus::FinalPublic; // Direct download link
        new_request.permanent = false;      
        return Ok(Json(new_request));
    }

    Err(WithReturnCode::new(extism_pdk::Error::msg("Not supported"), 404))
}


#[plugin_fn]
pub fn request_permanent(Json(request): Json<RsRequestPluginRequest>) -> FnResult<Json<RsRequest>> {
    if request.request.url.starts_with("magnet") {
        let token = &request.credential.and_then(|c| c.password)
            .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;

        let torrent_info = check_instant_internal(&request.request, token)?
            .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("Not available for instant download"), 404))?;

        log!(LogLevel::Debug, "Torrent Info {:?}\n\n", torrent_info );
        if torrent_info.files.as_ref().map(|f| f.len()).unwrap_or(0) > 1 && request.request.selected_file.is_none() {
            let mut result = request.request.clone();
            result.status = RsRequestStatus::NeedFileSelection;
            result.permanent = false;
            result.files = Some(torrent_info.files.unwrap_or_default().into_iter().map(|l| {
                let mut file = RsRequestFiles { name: l.short_name, size: l.size.max(0) as u64, mime: Some(l.mimetype), ..Default::default()};
                file.parse_filename();
                file
            }).collect());
            return Ok(Json(result));
        }

        // Check if already downloaded and cached
        let raw_hash = extract_btih_hash(&request.request.url)
            .ok_or_else(|| WithReturnCode(extism_pdk::Error::msg("Invalid magnet link: no BTIH hash found"), 400))?;
        let canonical_hash = get_canonical_hash(&raw_hash)?;
        log!(LogLevel::Info, "looking for existing hash {:?}\n", canonical_hash );
        let existing = match search_my_torrents(token, &canonical_hash, 20, None)? {
            Some(value) => Some(value),
            None => search_my_torrents(token, &canonical_hash, 20, Some(true))?,
        };

        log!(LogLevel::Debug, "In {:?}\n\n", existing );

        if let Some(t) = existing {
            if t.cached {
                
                let my_torrent_files = t.files.unwrap_or_default();
                if my_torrent_files.len() == 1 {
                    let file = &my_torrent_files[0];
                    log!(LogLevel::Info, "Single File already cached: {}", file.name);
                    // Already cached, return direct download link
                    let mut new_request = request.request.clone();
                    new_request.url = format!("torbox://api.torbox.app/v1/api/torrents/requestdl?token=_TOKEN_&redirect=true&torrent_id={}&file_id={}", t.id, file.id);
                    new_request.status = RsRequestStatus::FinalPublic; // Direct download link
                    new_request.permanent = true;   
                    new_request.mime = Some(file.mimetype.clone());   
                    return Ok(Json(new_request));
                } else if let Some(file) = my_torrent_files.iter().find(|f| { f.short_name == request.request.selected_file.clone().unwrap_or_default() || f.name == request.request.selected_file.clone().unwrap_or_default() }) {
                    log!(LogLevel::Info, "File already cached: {}", file.name);
                    // Already cached, return direct download link
                    let mut new_request = request.request.clone();
                    new_request.url = format!("torbox://api.torbox.app/v1/api/torrents/requestdl?token=_TOKEN_&redirect=true&torrent_id={}&file_id={}", t.id, file.id);
                    new_request.status = RsRequestStatus::FinalPublic; // Direct download link
                    new_request.permanent = true;      
                    new_request.mime = Some(file.mimetype.clone());
                    return Ok(Json(new_request));
                }
            }
        }


        log!(LogLevel::Info, "Getting file download link by adding it to your torrents {:?}\n", canonical_hash );
        let (url, file) = get_file_download_url(&request.request, &torrent_info, token, true)?;
        let mut final_request = request.request.clone();
        final_request.url = url;
        final_request.status = RsRequestStatus::FinalPublic;
        final_request.permanent = true;
        final_request.mime = Some(file.mimetype.clone());
        final_request.filename = Some(file.name.clone());
        Ok(Json(final_request))
    } else if request.request.url.starts_with("https://api.torbox.app/v1/api/torrents/requestdl") {
        let token = &request.credential.and_then(|c| c.password)
            .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;
        let mut new_request = request.request.clone();
        new_request.url = request.request.url.replacen("https://", "torbox://", 1).replace(token, "_TOKEN_");
        new_request.status = RsRequestStatus::FinalPublic; // Direct download link
        new_request.permanent = true;      
        return Ok(Json(new_request));
    } else {
        Err(WithReturnCode::new(extism_pdk::Error::msg("Not supported"), 404))
    }
}

#[plugin_fn]
pub fn request_add(Json(request): Json<RsRequestPluginRequest>) -> FnResult<Json<RsRequestAddResponse>> {
    // Only supports magnet links
    if !request.request.url.starts_with("magnet:") {
        return Err(WithReturnCode::new(extism_pdk::Error::msg("Only magnet links are supported for request_add"), 400));
    }

    let token = request.credential
        .and_then(|c| c.password)
        .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;

    let torrent_id = create_torrent_for_download(&request.request.url, &token)?;

    // Get initial status
    let torrent = get_my_torrent(&token, torrent_id)?;
    let status = map_download_state_to_status(torrent.download_state.as_deref(), torrent.cached);

    // Return relative ETA in milliseconds (host will convert to absolute timestamp)
    let eta = torrent.eta.filter(|&e| e > 0).map(|e| e * 1000);

    Ok(Json(RsRequestAddResponse {
        processing_id: torrent_id.to_string(),
        status,
        eta,
    }))
}

#[plugin_fn]
pub fn get_progress(Json(request): Json<RsProcessingActionRequest>) -> FnResult<Json<RsProcessingProgress>> {
    let token = request.credential
        .and_then(|c| c.password)
        .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;

    let torrent_id: i32 = request.processing_id.parse()
        .map_err(|_| WithReturnCode::new(extism_pdk::Error::msg("Invalid processing_id"), 400))?;

    let torrent = get_my_torrent(&token, torrent_id)?;

    let status = map_download_state_to_status(torrent.download_state.as_deref(), torrent.cached);

    // Convert progress from 0.0-1.0 to 0-100
    let progress = (torrent.progress.unwrap_or(0.0) * 100.0) as u32;

    // Return relative ETA in milliseconds (host will convert to absolute timestamp)
    let eta = torrent.eta.filter(|&e| e > 0).map(|e| e * 1000);

    // If finished, construct the final request with download URL
    let final_request = if status == RsProcessingStatus::Finished {
        let selected_file = request.params.as_ref().and_then(|p| p.get("selected_file").map(|s| s.as_str()));
        match construct_final_request(&torrent, selected_file) {
            Ok(req) => Some(Box::new(req)),
            Err(e) => {
                log!(LogLevel::Warn, "Failed to construct final request: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    Ok(Json(RsProcessingProgress {
        processing_id: request.processing_id,
        progress,
        status,
        error: None,
        eta,
        request: final_request,
    }))
}

#[plugin_fn]
pub fn pause(Json(request): Json<RsProcessingActionRequest>) -> FnResult<()> {
    let token = request.credential
        .and_then(|c| c.password)
        .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;

    let torrent_id: i32 = request.processing_id.parse()
        .map_err(|_| WithReturnCode::new(extism_pdk::Error::msg("Invalid processing_id"), 400))?;

    control_torrent(&token, torrent_id, "pause")
}

#[plugin_fn]
pub fn remove(Json(request): Json<RsProcessingActionRequest>) -> FnResult<()> {
    let token = request.credential
        .and_then(|c| c.password)
        .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("No token provided"), 401))?;

    let torrent_id: i32 = request.processing_id.parse()
        .map_err(|_| WithReturnCode::new(extism_pdk::Error::msg("Invalid processing_id"), 400))?;

    control_torrent(&token, torrent_id, "delete")
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

    let (search_query, season_episode) = match get_search_query_and_params(&lookup.query) {
        Ok(result) => result,
        Err(_) => return Ok(Json(RsLookupSourceResult::NotApplicable)),
    };
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
        let magnet = t.magnet.clone().unwrap_or_else(|| {
            format!("magnet:?xt=urn:btih:{}&dn={}", t.hash, encode(&t.title))
        });

        let r = RsRequest {
            url: magnet,
            permanent: true,
            instant: Some(t.cached),
            filename: Some(t.raw_title.clone()),
            language: t.title_parsed_data.language.as_ref().map(|l| match l {
                StringOrArray::Single(s) => s.clone(),
                StringOrArray::Array(vs) => vs.join(", "),
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
            size: Some(t.size.max(0) as u64),
            ..Default::default()
        };
        // TODO: Set resolution, codec from quality if parsed
        requests.push(r);
    }

    if requests.is_empty() {
        Ok(Json(RsLookupSourceResult::NotFound))
    } else {
        Ok(Json(RsLookupSourceResult::Requests(requests)))
    }
}

fn get_search_query_and_params(query: &RsLookupQuery) -> FnResult<(String, Option<(u32, Option<u32>)>)> {
    match query {
        RsLookupQuery::Movie(m) => {
            if let Some(ids) = &m.ids {
                if let Some(id_str) = ids.imdb.as_ref().map(|u| format!("imdb:{}", u))
                    .or(ids.tmdb.map(|s| format!("tmdb:{}", s)))
                    .or(ids.tvdb.map(|u| format!("tvdb:{}", u))) {
                    return Ok((id_str, None));
                }
            }
            let name = m.name.clone()
                .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("Not supported"), 404))?;
            Ok((name, None))
        },
        RsLookupQuery::Episode(e) => {
            let ep_num = e.number.unwrap_or(1);
            if let Some(ids) = &e.ids {
                if let Some(id_str) = ids.imdb.as_ref().map(|u| format!("imdb:{}", u))
                    .or(ids.tmdb.map(|s| format!("tmdb:{}", s)))
                    .or(ids.tvdb.map(|u| format!("tvdb:{}", u))) {
                    return Ok((id_str, Some((e.season, Some(ep_num)))));
                }
            }
            let name = e.name.clone()
                .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("Not supported"), 404))?;
            let base_query = format!("{} S{:02}E{:02}", name, e.season, ep_num);
            Ok((base_query, None))
        },
        RsLookupQuery::SerieSeason(s) => {
            if let Some(ids) = &s.ids {
                if let Some(id_str) = ids.imdb.as_ref().map(|u| format!("imdb:{}", u))
                    .or(ids.tmdb.map(|s| format!("tmdb:{}", s)))
                    .or(ids.tvdb.map(|u| format!("tvdb:{}", u))) {
                    return Ok((id_str, Some((s.name.as_deref().and_then(|n| n.parse().ok()).unwrap_or(1), None))));
                }
            }
            let name = s.name.clone()
                .ok_or_else(|| WithReturnCode::new(extism_pdk::Error::msg("Not supported"), 404))?;
            Ok((format!("{} season", name), None))
        },
        _ => Err(WithReturnCode::new(extism_pdk::Error::msg("Not supported"), 404)),
    }
}


fn handle_magnet_request(request: &RsRequest, password: &str) -> FnResult<Json<RsRequest>> {
    match check_instant_internal(request, password)? {
        Some(torrent_info) => {
            if torrent_info.files.as_ref().map(|f| f.len()).unwrap_or(0) > 1 && request.selected_file.is_none() {
                let mut result = request.clone();
                result.status = RsRequestStatus::NeedFileSelection;
                result.files = Some(torrent_info.files.unwrap_or_default().into_iter().map(|l| {
                let mut file = RsRequestFiles { name: l.short_name, size: l.size.max(0) as u64, mime: Some(l.mimetype), ..Default::default()};
                    file.parse_filename();
                    file
                }).collect());
                result.parse_subfilenames();
                Ok(Json(result))
            } else {
                // instant available, get file download URL
                let (url, file) = get_file_download_url(request, &torrent_info, password, true)?;
                let download_url = url.replace("torbox://", "https://").replace("_TOKEN_", password);
                let mut new_request = request.clone();
                new_request.status = RsRequestStatus::FinalPublic;
                new_request.url = download_url;
                new_request.mime = Some(file.mimetype.clone());
                new_request.filename = Some(file.name.clone());
                new_request.permanent = false;
                Ok(Json(new_request))
            }
        },
        None => {
            // Not available for instant - mark as requiring add to torrent list
            let mut result = request.clone();
            result.status = RsRequestStatus::RequireAdd;
            Ok(Json(result))
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

fn check_instant_internal(request: &RsRequest, token: &str) -> FnResult<Option<TorrentInfo>> {
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


fn get_my_torrents(token: &str, limit: i32, bypass_cache: Option<bool>) -> FnResult<Vec<MyTorrent>> {
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));

    let req = HttpRequest {
        url: format!("https://api.torbox.app/v1/api/torrents/mylist?limit={}&bypass_cache={}", limit, bypass_cache.unwrap_or_default()),
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

fn search_my_torrents(token: &str, canonical_hash: &str, limit: i32, bypass_cache: Option<bool>) -> FnResult<Option<MyTorrent>> {
    Ok(get_my_torrents(token, limit, bypass_cache)?.iter().find(|t| t.hash.eq_ignore_ascii_case(&canonical_hash)).cloned())
}

fn get_my_torrent(token: &str, id: i32) -> FnResult<MyTorrent> {
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));

    let req = HttpRequest {
        url: format!("https://api.torbox.app/v1/api/torrents/mylist?id={}&bypass_cache=true", id),
        headers,
        method: Some("GET".into()),
    };

    let res = http::request::<()>(&req, None)?;

    if res.status_code() != 200 {
        let error_msg = String::from_utf8_lossy(&res.body()).to_string();
        return Err(WithReturnCode(extism_pdk::Error::msg(format!("HTTP error getting my torrent by id({}) {}: {}", id, res.status_code(), error_msg)), res.status_code() as i32));
    }

    let response: MyTorrentResponse = res.json()
        .map_err(|e| WithReturnCode(extism_pdk::Error::msg(format!("JSON get one of my torrent by id({}) parse error: {}\nBody:\n {}", id, e, String::from_utf8(res.body()).unwrap_or("no body".to_string()))), 500))?;

   Ok(response.data)
}

fn get_file_download_url(request: &RsRequest, torrent_info: &TorrentInfo, token: &str, permanent: bool) -> FnResult<(String, MyFile)> {

    let files = &torrent_info.files;

    if files.is_none() || files.as_ref().unwrap_or(&vec![]).is_empty() {
        return Err(WithReturnCode(extism_pdk::Error::msg("No files found in torrent"), 404));
    }

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


    let my_torrent = get_my_torrent(token, torrent_id)?;
    
    let my_torrent_files = my_torrent.files.unwrap_or_default();
    
    let file = if my_torrent_files.len() == 1 {
        &my_torrent_files[0]
    } else {
        my_torrent_files.iter().find(|f| { f.short_name == request.selected_file.clone().unwrap_or_default() || f.name == request.selected_file.clone().unwrap_or_default() }).ok_or(extism_pdk::Error::msg(format!("Add torrent - Unable to find file({:?}) in {:?}", request.selected_file, my_torrent_files)))?
    };
    let file_id = file.id;
    
    if permanent {
        // For permanent requests, we are done here
        return Ok((format!("torbox://api.torbox.app/v1/api/torrents/requestdl?token=_TOKEN_&redirect=true&torrent_id={}&file_id={}", torrent_id, file_id), file.clone()));
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

    Ok((dl_response.data, file.clone()))
}

/// Creates a torrent for async download (without add_only_if_cached flag)
fn create_torrent_for_download(magnet_url: &str, token: &str) -> FnResult<i32> {
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));
    headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());

    let magnet_encoded = encode(magnet_url);
    let body_str = format!("magnet={}", magnet_encoded);
    let body_vec = body_str.as_bytes().to_vec();

    let create_req = HttpRequest {
        url: "https://api.torbox.app/v1/api/torrents/createtorrent".to_string(),
        headers,
        method: Some("POST".into()),
    };

    let create_res = http::request::<Vec<u8>>(&create_req, Some(body_vec))?;

    if create_res.status_code() != 200 {
        let error_msg = String::from_utf8_lossy(&create_res.body()).to_string();
        return Err(WithReturnCode(extism_pdk::Error::msg(format!("Create torrent HTTP {}: {}", create_res.status_code(), error_msg)), create_res.status_code() as i32));
    }

    let create_response: CreateTorrentResponse = create_res.json()
        .map_err(|e| WithReturnCode(extism_pdk::Error::msg(format!("JSON parse error during create torrent: {}", e)), 500))?;

    if let Some(err_msg) = create_response.error {
        return Err(WithReturnCode(extism_pdk::Error::msg(err_msg), 500));
    }

    Ok(create_response.data.torrent_id)
}

fn is_not_found_message(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("not found")
        || normalized.contains("no torrent")
        || normalized.contains("does not exist")
        || normalized.contains("doesn't exist")
}

fn is_idempotent_delete_error(error: &str, detail: &str) -> bool {
    is_not_found_message(error)
        || is_not_found_message(detail)
        || detail.eq_ignore_ascii_case("DATABASE_ERROR")
}

fn is_torrent_absent(token: &str, torrent_id: i32) -> FnResult<bool> {
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));

    let req = HttpRequest {
        url: format!("https://api.torbox.app/v1/api/torrents/mylist?id={}&bypass_cache=true", torrent_id),
        headers,
        method: Some("GET".into()),
    };

    let res = http::request::<()>(&req, None)?;
    let body = String::from_utf8_lossy(&res.body()).to_string();

    if res.status_code() == 404 {
        return Ok(true);
    }

    if res.status_code() == 500 && body.trim().is_empty() {
        return Ok(true);
    }

    if let Ok(response) = res.json::<TorboxStatusResponse>() {
        if response.success == Some(false) {
            let message = response
                .error
                .or(response.detail)
                .unwrap_or_default();
            return Ok(is_not_found_message(&message));
        }
    }

    if res.status_code() != 200 {
        return Ok(is_not_found_message(&body));
    }

    Ok(false)
}

/// Controls a torrent (pause or delete)
fn control_torrent(token: &str, torrent_id: i32, operation: &str) -> FnResult<()> {
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    let body = format!(r#"{{"torrent_id": {}, "operation": "{}"}}"#, torrent_id, operation);
    let body_vec = body.as_bytes().to_vec();

    let req = HttpRequest {
        url: "https://api.torbox.app/v1/api/torrents/controltorrent".to_string(),
        headers,
        method: Some("POST".into()),
    };

    let res = http::request::<Vec<u8>>(&req, Some(body_vec))?;

    if res.status_code() != 200 {
        let error_msg = String::from_utf8_lossy(&res.body()).to_string();
        let parsed_error = res.json::<TorboxStatusResponse>().ok();
        let has_idempotent_delete_error = parsed_error
            .as_ref()
            .map(|response| {
                is_idempotent_delete_error(
                    response.error.as_deref().unwrap_or_default(),
                    response.detail.as_deref().unwrap_or_default(),
                )
            })
            .unwrap_or(false);
        if operation == "delete"
            && (has_idempotent_delete_error
                || (res.status_code() == 500 && error_msg.trim().is_empty())
                || is_torrent_absent(token, torrent_id).unwrap_or(false))
        {
            return Ok(());
        }
        return Err(WithReturnCode(extism_pdk::Error::msg(format!("Control torrent HTTP {}: {}", res.status_code(), error_msg)), res.status_code() as i32));
    }

    let response: ControlTorrentResponse = res.json()
        .map_err(|e| WithReturnCode(extism_pdk::Error::msg(format!("JSON parse error during control torrent: {}", e)), 500))?;

    if !response.success {
        let response_detail = response.detail.clone();
        let response_error = response.error.unwrap_or(response_detail.clone());
        if operation == "delete"
            && (is_idempotent_delete_error(&response_error, &response_detail)
                || is_torrent_absent(token, torrent_id).unwrap_or(false))
        {
            return Ok(());
        }
        return Err(WithReturnCode(extism_pdk::Error::msg(response_error), 500));
    }

    Ok(())
}

/// Maps Torbox download_state to RsProcessingStatus
fn map_download_state_to_status(download_state: Option<&str>, cached: bool) -> RsProcessingStatus {
    if cached {
        return RsProcessingStatus::Finished;
    }

    match download_state {
        Some("downloading") | Some("metaDL") | Some("checking") | Some("queued") => RsProcessingStatus::Processing,
        Some("completed") | Some("uploading") | Some("seeding") => RsProcessingStatus::Finished,
        Some("paused") | Some("stalled") => RsProcessingStatus::Paused,
        Some("error") | Some("failed") => RsProcessingStatus::Error,
        _ => RsProcessingStatus::Processing, // Default to processing for unknown states
    }
}

/// Constructs the final RsRequest with download URL when torrent is finished
fn construct_final_request(torrent: &MyTorrent, selected_file: Option<&str>) -> FnResult<RsRequest> {
    let files = torrent.files.as_ref().ok_or_else(||
        WithReturnCode(extism_pdk::Error::msg("No files found in torrent"), 404))?;

    if files.is_empty() {
        return Err(WithReturnCode(extism_pdk::Error::msg("No files found in torrent"), 404));
    }

    let file = if files.len() == 1 {
        &files[0]
    } else if let Some(selected) = selected_file {
        files.iter()
            .find(|f| f.short_name == selected || f.name == selected)
            .ok_or_else(|| WithReturnCode(extism_pdk::Error::msg(format!("Selected file '{}' not found", selected)), 404))?
    } else {
        // Pick the largest file
        files.iter()
            .max_by_key(|f| f.size)
            .ok_or_else(|| WithReturnCode(extism_pdk::Error::msg("No files found"), 404))?
    };

    let url = format!(
        "torbox://api.torbox.app/v1/api/torrents/requestdl?token=_TOKEN_&redirect=true&torrent_id={}&file_id={}",
        torrent.id, file.id
    );

    Ok(RsRequest {
        url,
        status: RsRequestStatus::FinalPublic,
        permanent: true,
        mime: Some(file.mimetype.clone()),
        filename: Some(file.name.clone()),
        size: Some(file.size.max(0) as u64),
        ..Default::default()
    })
}
